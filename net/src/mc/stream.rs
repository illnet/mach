use super::{
    error::Result,
    packets::{
        ClientboundPacket, HandshakeC2s, LoginStartC2s, PacketKind, ServerboundPacket,
        packet_kind_for,
    },
    state::{HandshakeNextState, PacketDirection, PacketState, StreamAuthMode, StreamSecurity},
    types::{PacketDecoder, PacketFrame},
};

/// Metadata emitted for WAF-style packet inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    pub direction: PacketDirection,
    pub state: PacketState,
    pub protocol_version: Option<i32>,
    pub id: i32,
    pub kind: PacketKind,
    pub body_len: usize,
    pub security: StreamSecurity,
    pub auth_mode: StreamAuthMode,
    pub compression_threshold: Option<i32>,
}

/// Parsed packet plus stable metadata for hook consumers.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketEvent<'a> {
    pub meta: PacketMeta,
    pub packet: ParsedPacket<'a>,
}

/// Direction-aware packet box. Unknown keeps raw body in the original [`PacketFrame`].
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedPacket<'a> {
    Serverbound(ServerboundPacket<'a>),
    Clientbound(ClientboundPacket<'a>),
    Unknown,
}

/// Reactive packet listener for shielding/rule engines.
pub trait PacketHook {
    fn on_packet(&mut self, event: PacketEvent<'_>);
}

/// Stateful Minecraft stream parser for pre-crypto packet inspection.
pub struct MinecraftStreamParser {
    decoder: PacketDecoder,
    state: PacketState,
    protocol_version: Option<i32>,
    security: StreamSecurity,
    auth_mode: StreamAuthMode,
    compression_threshold: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
enum Transition {
    None,
    Handshake {
        protocol_version: i32,
        next_state: HandshakeNextState,
    },
    LoginStart,
    EncryptionRequest {
        should_authenticate: Option<bool>,
    },
    EncryptionResponse,
    SetCompression {
        threshold: i32,
    },
    LoginSuccess,
    JoinGame,
}

impl Default for MinecraftStreamParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MinecraftStreamParser {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            decoder: PacketDecoder::new(),
            state: PacketState::Handshaking,
            protocol_version: None,
            security: StreamSecurity::Plain,
            auth_mode: StreamAuthMode::Unknown,
            compression_threshold: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> PacketState {
        self.state
    }

    #[must_use]
    pub const fn protocol_version(&self) -> Option<i32> {
        self.protocol_version
    }

    #[must_use]
    pub const fn security(&self) -> StreamSecurity {
        self.security
    }

    #[must_use]
    pub const fn auth_mode(&self) -> StreamAuthMode {
        self.auth_mode
    }

    #[must_use]
    pub const fn compression_threshold(&self) -> Option<i32> {
        self.compression_threshold
    }

    pub fn queue_slice(&mut self, bytes: &[u8]) {
        self.decoder.queue_slice(bytes);
    }

    pub fn take_pending_bytes(&mut self) -> Vec<u8> {
        self.decoder.take_pending_bytes()
    }

    /// Mark encryption active after caller installs ciphers. Encrypted length fields cannot be
    /// parsed by this zero-dependency stream parser.
    pub fn note_encryption_enabled(&mut self) {
        self.security = StreamSecurity::Encrypted;
    }

    pub fn try_next_with_hook<H: PacketHook>(
        &mut self,
        direction: PacketDirection,
        hook: &mut H,
    ) -> Result<bool> {
        let Some(frame) = self.decoder.try_next_packet()? else {
            return Ok(false);
        };
        let protocol_version = self.protocol_version.unwrap_or_default();
        let kind = packet_kind_for(self.state, direction, protocol_version, frame.id);
        let event = self.parse_frame(direction, kind, &frame)?;
        let transition = Self::transition_from_event(&event);
        hook.on_packet(event);
        self.apply_transition(transition);
        Ok(true)
    }

    pub fn drain_with_hook<H: PacketHook>(
        &mut self,
        direction: PacketDirection,
        hook: &mut H,
    ) -> Result<usize> {
        let mut count = 0usize;
        while self.try_next_with_hook(direction, hook)? {
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    fn parse_frame<'a>(
        &self,
        direction: PacketDirection,
        kind: PacketKind,
        frame: &'a PacketFrame,
    ) -> Result<PacketEvent<'a>> {
        let protocol_version = self.protocol_version.unwrap_or_default();
        let packet = match direction {
            PacketDirection::C2s => {
                ServerboundPacket::decode_known(self.state, protocol_version, kind, frame)?
                    .map_or(ParsedPacket::Unknown, ParsedPacket::Serverbound)
            }
            PacketDirection::S2c => {
                ClientboundPacket::decode_known(self.state, protocol_version, kind, frame)?
                    .map_or(ParsedPacket::Unknown, ParsedPacket::Clientbound)
            }
        };

        Ok(PacketEvent {
            meta: PacketMeta {
                direction,
                state: self.state,
                protocol_version: self.protocol_version,
                id: frame.id,
                kind,
                body_len: frame.body.len(),
                security: self.security,
                auth_mode: self.auth_mode,
                compression_threshold: self.compression_threshold,
            },
            packet,
        })
    }

    fn transition_from_event(event: &PacketEvent<'_>) -> Transition {
        match &event.packet {
            ParsedPacket::Serverbound(ServerboundPacket::Handshake(HandshakeC2s {
                protocol_version,
                next_state,
                ..
            })) => Transition::Handshake {
                protocol_version: *protocol_version,
                next_state: *next_state,
            },
            ParsedPacket::Serverbound(ServerboundPacket::LoginStart(LoginStartC2s { .. })) => {
                Transition::LoginStart
            }
            ParsedPacket::Serverbound(ServerboundPacket::EncryptionResponse(_)) => {
                Transition::EncryptionResponse
            }
            ParsedPacket::Clientbound(ClientboundPacket::EncryptionRequest(request)) => {
                Transition::EncryptionRequest {
                    should_authenticate: request.should_authenticate,
                }
            }
            ParsedPacket::Clientbound(ClientboundPacket::SetCompression(packet)) => {
                Transition::SetCompression {
                    threshold: packet.threshold,
                }
            }
            ParsedPacket::Clientbound(ClientboundPacket::LoginSuccess(_)) => {
                Transition::LoginSuccess
            }
            ParsedPacket::Clientbound(ClientboundPacket::JoinGame(_)) => Transition::JoinGame,
            _ => Transition::None,
        }
    }

    fn apply_transition(&mut self, transition: Transition) {
        match transition {
            Transition::None => {}
            Transition::Handshake {
                protocol_version,
                next_state,
            } => {
                self.protocol_version = Some(protocol_version);
                self.state = match next_state {
                    HandshakeNextState::Status => PacketState::Status,
                    HandshakeNextState::Login => PacketState::Login,
                };
            }
            Transition::LoginStart => {
                if self.auth_mode == StreamAuthMode::Unknown {
                    self.auth_mode = StreamAuthMode::Offline;
                }
            }
            Transition::EncryptionRequest {
                should_authenticate,
            } => {
                self.security = StreamSecurity::EncryptionRequested;
                self.auth_mode = if should_authenticate == Some(false) {
                    StreamAuthMode::OfflineEncryption
                } else {
                    StreamAuthMode::OnlineRequested
                };
            }
            Transition::EncryptionResponse => {
                self.security = StreamSecurity::EncryptionResponseSeen;
            }
            Transition::SetCompression { threshold } => {
                self.compression_threshold = Some(threshold);
            }
            Transition::LoginSuccess => {
                self.state = if self.protocol_version.unwrap_or_default() >= 764 {
                    PacketState::Configuration
                } else {
                    PacketState::Play
                };
            }
            Transition::JoinGame => {
                self.state = PacketState::Play;
            }
        }
    }
}

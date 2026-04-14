/// Protocol state used to select packet IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketState {
    Handshaking,
    Status,
    Login,
    Configuration,
    Play,
}

/// Next state value in the handshake packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeNextState {
    Status,
    Login,
}

/// Packet direction label used by stream metadata and hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    C2s,
    S2c,
}

/// Authentication mode inferred from the login exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAuthMode {
    Unknown,
    Offline,
    OnlineRequested,
    OfflineEncryption,
}

/// Encryption progress inferred by the stream parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSecurity {
    Plain,
    EncryptionRequested,
    EncryptionResponseSeen,
    Encrypted,
}

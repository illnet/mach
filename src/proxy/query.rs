use net::{StatusPingC2s, StatusPongS2c};
use serde_json::json;

use crate::{
    config::LureConfig,
    connection::EncodedConnection,
    threat::{ClientFail, ClientIntent, IntentTag, ThreatControlService},
};

fn string_or_fallback(config: &LureConfig, key: &str, fallback: &str) -> String {
    let value = config.string_value(key);
    let value = value.as_ref();
    let missing_marker = format!("{key}-is-not-written");
    if value == missing_marker {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

/// Builds minimal Status response JSON body.
pub fn placeholder_status_response(brand: &str, message: &str) -> String {
    json!({
        "version": {
            "name": brand,
            "protocol": -1
        },
        "description": {
            "text": message
        }
    })
    .to_string()
}

/// Builds configured fallback Status response JSON.
pub fn placeholder_status_json(config: &LureConfig, label: &str) -> String {
    placeholder_status_json_with_fallback(config, label, "Gateway error")
}

/// Builds configured Status response JSON with explicit fallback message.
pub fn placeholder_status_json_with_fallback(
    config: &LureConfig,
    label: &str,
    fallback: &str,
) -> String {
    let brand = string_or_fallback(config, "SERVER_LIST_BRAND", "Lure");
    let target_label = string_or_fallback(config, label, fallback);
    placeholder_status_response(&brand, &target_label)
}

/// Sends placeholder Status response for failure cases.
pub async fn send_status_failure(
    client: &mut EncodedConnection,
    config: &LureConfig,
    label: &str,
) -> anyhow::Result<()> {
    let placeholder = placeholder_status_json(config, label);
    client
        .send(&net::StatusResponseS2c { json: &placeholder })
        .await?;
    Ok(())
}

/// Sends placeholder Status response with caller-provided fallback text.
pub async fn send_status_failure_with_fallback(
    client: &mut EncodedConnection,
    config: &LureConfig,
    label: &str,
    fallback: &str,
) -> anyhow::Result<()> {
    let placeholder = placeholder_status_json_with_fallback(config, label, fallback);
    client
        .send(&net::StatusResponseS2c { json: &placeholder })
        .await?;
    Ok(())
}

/// Send a cached or computed status response from raw JSON bytes
pub async fn send_status_response(
    client: &mut EncodedConnection,
    json_bytes: &[u8],
) -> anyhow::Result<()> {
    // Convert bytes to string for sending (StatusResponseS2c expects &str)
    let json_str = std::str::from_utf8(json_bytes)?;
    client
        .send(&net::StatusResponseS2c { json: json_str })
        .await?;
    Ok(())
}

/// Handle ping/pong locally by echoing the client's timestamp
pub async fn handle_ping_pong_local(
    client: &mut EncodedConnection,
    threat: &ThreatControlService,
) -> anyhow::Result<()> {
    let intent = ClientIntent {
        tag: IntentTag::Query,
        duration: std::time::Duration::from_secs(1),
    };

    let ping = match threat
        .nuisance(client.recv::<StatusPingC2s>(), intent)
        .await
    {
        Ok(Ok(packet)) => packet,
        Ok(Err(err)) => return Err(err),
        Err(err) => {
            if err.downcast_ref::<ClientFail>().is_some() {
                return Err(err);
            }
            return Err(err);
        }
    };

    // Echo the ping payload back in the pong response
    client
        .send(&StatusPongS2c {
            payload: ping.payload,
        })
        .await?;
    Ok(())
}

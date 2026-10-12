use crate::crypto::{sha512_digest, SessionKeys, Ukey2KeyExchange};
use crate::proto::wire::{
    ukey2_client_init::CipherCommitment, ukey2_message::Type as Ukey2Type, Ukey2ClientFinished,
    Ukey2ClientInit, Ukey2HandshakeCipher, Ukey2Message, Ukey2ServerInit,
};
use crate::transport::{read_length_prefixed_frame, write_length_prefixed_frame};
use anyhow::{anyhow, Result};
use prost::Message;
use rand::{rngs::OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};

/// Perform UKEY2 Handshake as Server (Responder)
pub async fn perform_ukey2_handshake_server<S>(stream: &mut S) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("Starting UKEY2 handshake as responder (Server)...");

    // 1. Read ClientInit
    let raw_msg1 = read_length_prefixed_frame(stream).await?;
    let msg1 = Ukey2Message::decode(&raw_msg1[..])
        .map_err(|e| anyhow!("Failed to decode UKEY2 Message 1: {:?}", e))?;

    if msg1.message_type() != Ukey2Type::ClientInit {
        return Err(anyhow!(
            "Expected UKEY2 ClientInit (type 2), got {:?}",
            msg1.message_type()
        ));
    }

    let client_init_bytes = msg1
        .message_data
        .ok_or_else(|| anyhow!("UKEY2 Message 1 missing message_data"))?;
    let client_init = Ukey2ClientInit::decode(&client_init_bytes[..])
        .map_err(|e| anyhow!("Failed to decode Ukey2ClientInit: {:?}", e))?;

    if client_init.version() != 1 {
        return Err(anyhow!(
            "Unsupported UKEY2 version: {}",
            client_init.version()
        ));
    }

    let client_random = client_init
        .random
        .ok_or_else(|| anyhow!("ClientInit missing random"))?;
    if client_random.len() != 32 {
        return Err(anyhow!(
            "Invalid ClientInit random length: {}",
            client_random.len()
        ));
    }

    // Find P256_SHA512 commitment
    let mut selected_commitment: Option<Vec<u8>> = None;
    for commitment in &client_init.cipher_commitments {
        if commitment.handshake_cipher() == Ukey2HandshakeCipher::P256Sha512 {
            selected_commitment = commitment.commitment.clone();
            break;
        }
    }

    let expected_commitment = selected_commitment.ok_or_else(|| {
        anyhow!("Client did not propose P256_SHA512 handshake cipher")
    })?;

    // 2. Generate ServerInit
    let kx = Ukey2KeyExchange::new();
    let mut server_random = vec![0u8; 32];
    OsRng.fill_bytes(&mut server_random);

    let pub_key_bytes = kx.encode_public_key();

    let server_init = Ukey2ServerInit {
        version: Some(1),
        random: Some(server_random),
        handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
        public_key: Some(pub_key_bytes),
    };

    let mut server_init_bytes = Vec::new();
    server_init.encode(&mut server_init_bytes)?;

    let msg2 = Ukey2Message {
        message_type: Some(Ukey2Type::ServerInit as i32),
        message_data: Some(server_init_bytes),
    };

    let mut raw_msg2 = Vec::new();
    msg2.encode(&mut raw_msg2)?;
    write_length_prefixed_frame(stream, &raw_msg2).await?;
    debug!("Sent UKEY2 ServerInit (Message 2)");

    // 3. Read ClientFinish
    let raw_msg3 = read_length_prefixed_frame(stream).await?;
    let msg3 = Ukey2Message::decode(&raw_msg3[..])
        .map_err(|e| anyhow!("Failed to decode UKEY2 Message 3: {:?}", e))?;

    if msg3.message_type() != Ukey2Type::ClientFinish {
        return Err(anyhow!(
            "Expected UKEY2 ClientFinish (type 4), got {:?}",
            msg3.message_type()
        ));
    }

    // Verify commitment: commitment == SHA512(raw_msg3)
    let digest = sha512_digest(&raw_msg3);
    if digest.as_slice() != expected_commitment.as_slice() {
        return Err(anyhow!("UKEY2 cipher commitment verification failed"));
    }

    let client_finish_bytes = msg3
        .message_data
        .ok_or_else(|| anyhow!("UKEY2 Message 3 missing message_data"))?;
    let client_finish = Ukey2ClientFinished::decode(&client_finish_bytes[..])
        .map_err(|e| anyhow!("Failed to decode Ukey2ClientFinished: {:?}", e))?;

    let client_pub_bytes = client_finish
        .public_key
        .ok_or_else(|| anyhow!("Ukey2ClientFinished missing public_key"))?;

    let session_keys = kx.complete_server_exchange(
        &client_pub_bytes,
        &raw_msg1,
        &raw_msg2,
    )?;

    info!(
        "Server UKEY2 Handshake Succeeded! 4-Digit PIN: [{}]",
        session_keys.pin
    );
    Ok(session_keys)
}

/// Perform UKEY2 Handshake as Client (Initiator)
pub async fn perform_ukey2_handshake_client<S>(stream: &mut S) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("Starting UKEY2 handshake as initiator (Client)...");

    let kx = Ukey2KeyExchange::new();
    let mut client_random = vec![0u8; 32];
    OsRng.fill_bytes(&mut client_random);

    // Prepare ClientFinished ahead of time for commitment
    let pub_key_bytes = kx.encode_public_key();
    let client_finished = Ukey2ClientFinished {
        public_key: Some(pub_key_bytes),
    };
    let mut client_finished_bytes = Vec::new();
    client_finished.encode(&mut client_finished_bytes)?;

    let msg3 = Ukey2Message {
        message_type: Some(Ukey2Type::ClientFinish as i32),
        message_data: Some(client_finished_bytes),
    };
    let mut raw_msg3 = Vec::new();
    msg3.encode(&mut raw_msg3)?;

    let commitment = sha512_digest(&raw_msg3);

    // 1. Send ClientInit
    let client_init = Ukey2ClientInit {
        version: Some(1),
        random: Some(client_random),
        cipher_commitments: vec![CipherCommitment {
            handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
            commitment: Some(commitment.to_vec()),
        }],
        next_protocol: Some("AES_256_CBC-HMAC_SHA256".to_string()),
    };
    let mut client_init_bytes = Vec::new();
    client_init.encode(&mut client_init_bytes)?;

    let msg1 = Ukey2Message {
        message_type: Some(Ukey2Type::ClientInit as i32),
        message_data: Some(client_init_bytes),
    };
    let mut raw_msg1 = Vec::new();
    msg1.encode(&mut raw_msg1)?;
    write_length_prefixed_frame(stream, &raw_msg1).await?;
    debug!("Sent UKEY2 ClientInit (Message 1)");

    // 2. Read ServerInit
    let raw_msg2 = read_length_prefixed_frame(stream).await?;
    let msg2 = Ukey2Message::decode(&raw_msg2[..])
        .map_err(|e| anyhow!("Failed to decode UKEY2 Message 2: {:?}", e))?;

    if msg2.message_type() != Ukey2Type::ServerInit {
        return Err(anyhow!(
            "Expected UKEY2 ServerInit (type 3), got {:?}",
            msg2.message_type()
        ));
    }

    let server_init_bytes = msg2
        .message_data
        .ok_or_else(|| anyhow!("UKEY2 Message 2 missing message_data"))?;
    let server_init = Ukey2ServerInit::decode(&server_init_bytes[..])
        .map_err(|e| anyhow!("Failed to decode Ukey2ServerInit: {:?}", e))?;

    let server_pub_bytes = server_init
        .public_key
        .ok_or_else(|| anyhow!("ServerInit missing public_key"))?;

    // 3. Send ClientFinish
    write_length_prefixed_frame(stream, &raw_msg3).await?;
    debug!("Sent UKEY2 ClientFinish (Message 3)");

    let session_keys = kx.complete_client_exchange(
        &server_pub_bytes,
        &raw_msg1,
        &raw_msg2,
    )?;

    info!(
        "Client UKEY2 Handshake Succeeded! 4-Digit PIN: [{}]",
        session_keys.pin
    );
    Ok(session_keys)
}

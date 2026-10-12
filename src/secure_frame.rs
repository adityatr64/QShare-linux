use crate::crypto::{
    aes_256_cbc_decrypt, aes_256_cbc_encrypt, hmac_sha256_sign, hmac_sha256_verify, SessionKeys,
};
use crate::proto::wire::{
    header::{EncScheme, SigScheme},
    DeviceToDeviceMessage, Header, HeaderAndBody, OfflineFrame, SecureMessage,
};
use anyhow::{anyhow, Result};
use prost::Message;
use rand::{rngs::OsRng, RngCore};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProtocolRole {
    Server,
    Client,
}

pub fn decrypt_secure_frame(
    keys: &SessionKeys,
    raw_frame: &[u8],
    role: ProtocolRole,
) -> Result<(OfflineFrame, i32)> {
    let secure_msg = SecureMessage::decode(raw_frame)
        .map_err(|e| anyhow!("Failed to decode SecureMessage: {:?}", e))?;

    let header_and_body_bytes = secure_msg
        .header_and_body
        .ok_or_else(|| anyhow!("SecureMessage missing header_and_body"))?;
    let signature = secure_msg
        .signature
        .ok_or_else(|| anyhow!("SecureMessage missing signature"))?;

    // Incoming verification key
    let (hmac_key, dec_key) = match role {
        ProtocolRole::Server => (&keys.client_hmac_key, &keys.client_key),
        ProtocolRole::Client => (&keys.server_hmac_key, &keys.server_key),
    };

    // Verify HMAC-SHA256 signature
    hmac_sha256_verify(hmac_key, &header_and_body_bytes, &signature)?;

    let header_and_body = HeaderAndBody::decode(&header_and_body_bytes[..])
        .map_err(|e| anyhow!("Failed to decode HeaderAndBody: {:?}", e))?;

    let header = header_and_body
        .header
        .ok_or_else(|| anyhow!("HeaderAndBody missing header"))?;
    let iv = header.iv.ok_or_else(|| anyhow!("Header missing IV"))?;
    let ciphertext = header_and_body
        .body
        .ok_or_else(|| anyhow!("HeaderAndBody missing body ciphertext"))?;

    // Decrypt AES-256-CBC
    let plaintext = aes_256_cbc_decrypt(dec_key, &iv, &ciphertext)?;

    // Parse DeviceToDeviceMessage
    let d2d_msg = DeviceToDeviceMessage::decode(&plaintext[..])
        .map_err(|e| anyhow!("Failed to decode DeviceToDeviceMessage: {:?}", e))?;

    let offline_frame_bytes = d2d_msg
        .message
        .ok_or_else(|| anyhow!("DeviceToDeviceMessage missing inner message"))?;
    let seq = d2d_msg.sequence_number.unwrap_or(0);

    let offline_frame = OfflineFrame::decode(&offline_frame_bytes[..])
        .map_err(|e| anyhow!("Failed to decode OfflineFrame: {:?}", e))?;

    Ok((offline_frame, seq))
}

pub fn encrypt_secure_frame(
    keys: &SessionKeys,
    frame: &OfflineFrame,
    seq: i32,
    role: ProtocolRole,
) -> Result<Vec<u8>> {
    let mut offline_frame_bytes = Vec::new();
    frame.encode(&mut offline_frame_bytes)?;

    let d2d_msg = DeviceToDeviceMessage {
        message: Some(offline_frame_bytes),
        sequence_number: Some(seq),
    };
    let mut plaintext = Vec::new();
    d2d_msg.encode(&mut plaintext)?;

    // Generate random IV
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    // Outgoing encryption key
    let (enc_key, hmac_key) = match role {
        ProtocolRole::Server => (&keys.server_key, &keys.server_hmac_key),
        ProtocolRole::Client => (&keys.client_key, &keys.client_hmac_key),
    };

    // Encrypt AES-256-CBC
    let ciphertext = aes_256_cbc_encrypt(enc_key, &iv, &plaintext)?;

    let header = Header {
        signature_scheme: Some(SigScheme::HmacSha256 as i32),
        encryption_scheme: Some(EncScheme::Aes256Cbc as i32),
        verification_key_id: None,
        decryption_key_id: None,
        iv: Some(iv.to_vec()),
        public_metadata: Some(vec![0x08, 0x0d, 0x10, 0x01]), // GcmMetadata: type=DEVICE_TO_DEVICE_MESSAGE (13), version=1
        associated_data_length: None,
    };

    let header_and_body = HeaderAndBody {
        header: Some(header),
        body: Some(ciphertext),
    };
    let mut header_and_body_bytes = Vec::new();
    header_and_body.encode(&mut header_and_body_bytes)?;

    // Sign with hmac_key
    let signature = hmac_sha256_sign(hmac_key, &header_and_body_bytes)?;

    let secure_msg = SecureMessage {
        header_and_body: Some(header_and_body_bytes),
        signature: Some(signature),
    };

    let mut out = Vec::new();
    secure_msg.encode(&mut out)?;
    Ok(out)
}

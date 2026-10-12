use aes::Aes256;
use anyhow::{anyhow, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct SessionKeys {
    pub client_key: [u8; 32],
    pub client_hmac_key: [u8; 32],
    pub server_key: [u8; 32],
    pub server_hmac_key: [u8; 32],
    pub auth_token: [u8; 32],
    pub pin: String,
}

pub struct Ukey2KeyExchange {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl Ukey2KeyExchange {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    /// Complete exchange from Server (responder) side
    pub fn complete_server_exchange(
        self,
        client_pub_bytes: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> Result<SessionKeys> {
        self.derive_session_keys(client_pub_bytes, client_random, server_random)
    }

    /// Complete exchange from Client (initiator) side
    pub fn complete_client_exchange(
        self,
        server_pub_bytes: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> Result<SessionKeys> {
        self.derive_session_keys(server_pub_bytes, client_random, server_random)
    }

    fn derive_session_keys(
        self,
        peer_pub_bytes: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> Result<SessionKeys> {
        if peer_pub_bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid peer public key length: expected 32 bytes, got {}",
                peer_pub_bytes.len()
            ));
        }

        let mut peer_arr = [0u8; 32];
        peer_arr.copy_from_slice(peer_pub_bytes);
        let peer_pub = PublicKey::from(peer_arr);

        // Diffie-Hellman shared secret
        let shared_secret = self.secret.diffie_hellman(&peer_pub);

        // Salt = client_random || server_random
        let mut salt = Vec::with_capacity(client_random.len() + server_random.len());
        salt.extend_from_slice(client_random);
        salt.extend_from_slice(server_random);

        // PRK = HKDF-Extract(salt, IKM)
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());

        // UKEY2 v1 auth token (32 bytes)
        let mut auth_token = [0u8; 32];
        hk.expand(b"UKEY2 v1 auth", &mut auth_token)
            .map_err(|e| anyhow!("HKDF expand auth failed: {:?}", e))?;

        // UKEY2 v1 next secret (32 bytes)
        let mut next_secret = [0u8; 32];
        hk.expand(b"UKEY2 v1 next", &mut next_secret)
            .map_err(|e| anyhow!("HKDF expand next failed: {:?}", e))?;

        // 4-Digit Authentication PIN
        let pin = compute_verification_pin(&auth_token);

        // Derive AES & HMAC keys from next_secret
        let hk_next = Hkdf::<Sha256>::new(None, &next_secret);
        let mut key_material = [0u8; 128];
        hk_next
            .expand(b"AES_256_CBC-HMAC_SHA256", &mut key_material)
            .map_err(|e| anyhow!("HKDF expand key material failed: {:?}", e))?;

        let mut client_key = [0u8; 32];
        let mut server_key = [0u8; 32];
        let mut client_hmac_key = [0u8; 32];
        let mut server_hmac_key = [0u8; 32];

        client_key.copy_from_slice(&key_material[0..32]);
        server_key.copy_from_slice(&key_material[32..64]);
        client_hmac_key.copy_from_slice(&key_material[64..96]);
        server_hmac_key.copy_from_slice(&key_material[96..128]);

        Ok(SessionKeys {
            client_key,
            client_hmac_key,
            server_key,
            server_hmac_key,
            auth_token,
            pin,
        })
    }
}

/// Exact Quick Share 4-digit PIN derivation algorithm
/// Reconstructed from binary disassembly of `nearby_share.exe` at offset `0x1404E2160`.
/// Accumulates signed 8-bit bytes modulo 9973 with multiplier 31.
pub fn compute_verification_pin(auth_token: &[u8]) -> String {
    let mut hash: i32 = 0;
    let mut multiplier: i32 = 1;

    for &byte in auth_token {
        let signed_byte = byte as i8 as i32;
        hash = (hash + signed_byte * multiplier) % 9973;
        multiplier = (multiplier * 31) % 9973;
    }

    format!("{:04}", hash.abs())
}

/// Compute SHA-512 commitment of bytes
pub fn sha512_digest(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// Decrypt AES-256-CBC ciphertext with PKCS#7 unpadding
pub fn aes_256_cbc_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != 16 {
        return Err(anyhow!("Invalid IV length for AES-CBC: {}", iv.len()));
    }
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let mut buf = ciphertext.to_vec();
    let pt = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow!("AES-256-CBC decryption failed: {:?}", e))?;
    Ok(pt.to_vec())
}

/// Encrypt plaintext with AES-256-CBC and PKCS#7 padding
pub fn aes_256_cbc_encrypt(key: &[u8; 32], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != 16 {
        return Err(anyhow!("Invalid IV length for AES-CBC: {}", iv.len()));
    }
    let encryptor = Aes256CbcEnc::new(key.into(), iv.into());
    let pt_len = plaintext.len();
    let block_size = 16;
    let padded_len = ((pt_len / block_size) + 1) * block_size;
    let mut buf = vec![0u8; padded_len];
    buf[..pt_len].copy_from_slice(plaintext);
    let ct = encryptor
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
        .map_err(|e| anyhow!("AES-256-CBC encryption failed: {:?}", e))?;
    Ok(ct.to_vec())
}

/// Verify HMAC-SHA256 signature
pub fn hmac_sha256_verify(key: &[u8; 32], data: &[u8], signature: &[u8]) -> Result<()> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow!("HMAC init error: {:?}", e))?;
    mac.update(data);
    mac.verify_slice(signature)
        .map_err(|e| anyhow!("HMAC signature verification failed: {:?}", e))?;
    Ok(())
}

/// Compute HMAC-SHA256 signature
pub fn hmac_sha256_sign(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow!("HMAC init error: {:?}", e))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

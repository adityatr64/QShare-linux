use aes::Aes256;
use anyhow::{anyhow, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{PublicKey, SecretKey};
use prost::Message;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

use crate::proto::wire::{EcP256PublicKey, GenericPublicKey, PublicKeyType};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const D2D_SALT: &[u8] = &[
    0x82, 0xaa, 0x55, 0xa0, 0xd3, 0x97, 0xf8, 0x83, 0x46, 0xca, 0x1c, 0xee, 0x8d, 0x39, 0x09,
    0xb9, 0x5f, 0x13, 0xfa, 0x7d, 0xeb, 0x1d, 0x4a, 0xb3, 0x83, 0x76, 0xb8, 0x25, 0x6d, 0xa8,
    0x55, 0x10,
];

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
    secret: SecretKey,
    pub public_key: PublicKey,
}

impl Ukey2KeyExchange {
    pub fn new() -> Self {
        let mut raw = [0u8; 32];
        let secret = loop {
            OsRng.fill_bytes(&mut raw);
            if let Ok(sk) = SecretKey::from_slice(&raw) {
                break sk;
            }
        };
        let public_key = secret.public_key();
        Self { secret, public_key }
    }

    /// Encode our public key as serialized GenericPublicKey Protobuf bytes
    pub fn encode_public_key(&self) -> Vec<u8> {
        encode_p256_public_key(&self.public_key)
    }

    /// Complete exchange from Server (responder) side
    pub fn complete_server_exchange(
        self,
        peer_generic_pub_bytes: &[u8],
        m1_bytes: &[u8],
        m2_bytes: &[u8],
    ) -> Result<SessionKeys> {
        let peer_pub = decode_p256_public_key(peer_generic_pub_bytes)?;
        self.derive_session_keys(&peer_pub, m1_bytes, m2_bytes)
    }

    /// Complete exchange from Client (initiator) side
    pub fn complete_client_exchange(
        self,
        peer_generic_pub_bytes: &[u8],
        m1_bytes: &[u8],
        m2_bytes: &[u8],
    ) -> Result<SessionKeys> {
        let peer_pub = decode_p256_public_key(peer_generic_pub_bytes)?;
        self.derive_session_keys(&peer_pub, m1_bytes, m2_bytes)
    }

    fn derive_session_keys(
        self,
        peer_pub: &PublicKey,
        m1_bytes: &[u8],
        m2_bytes: &[u8],
    ) -> Result<SessionKeys> {
        // Diffie-Hellman shared secret
        let shared_secret = p256::elliptic_curve::ecdh::diffie_hellman(
            self.secret.to_nonzero_scalar(),
            peer_pub.as_affine(),
        );
        let raw_secret = shared_secret.raw_secret_bytes();

        // dhs = Sha256(raw_shared_secret)
        let mut hasher = Sha256::new();
        hasher.update(raw_secret);
        let dhs = hasher.finalize();

        // info = m1 || m2 (raw wire frames of Message 1 and Message 2)
        let mut info = Vec::with_capacity(m1_bytes.len() + m2_bytes.len());
        info.extend_from_slice(m1_bytes);
        info.extend_from_slice(m2_bytes);

        // next_secret = HKDF-SHA256(ikm = dhs, salt = "UKEY2 v1 next", info = m1 || m2, len = 32)
        let hk_next = Hkdf::<Sha256>::new(Some(b"UKEY2 v1 next"), &dhs);
        let mut next_secret = [0u8; 32];
        hk_next
            .expand(&info, &mut next_secret)
            .map_err(|e| anyhow!("HKDF expand next_secret failed: {:?}", e))?;

        // auth_string = HKDF-SHA256(ikm = dhs, salt = "UKEY2 v1 auth", info = m1 || m2, len = 32)
        let hk_auth = Hkdf::<Sha256>::new(Some(b"UKEY2 v1 auth"), &dhs);
        let mut auth_token = [0u8; 32];
        hk_auth
            .expand(&info, &mut auth_token)
            .map_err(|e| anyhow!("HKDF expand auth_token failed: {:?}", e))?;

        // 4-Digit Authentication PIN
        let pin = compute_verification_pin(&auth_token);

        // D2D master keys from next_secret
        let hk_d2d = Hkdf::<Sha256>::new(Some(D2D_SALT), &next_secret);
        let mut d2d_server_key = [0u8; 32];
        hk_d2d
            .expand(b"server", &mut d2d_server_key)
            .map_err(|e| anyhow!("HKDF expand d2d_server_key failed: {:?}", e))?;

        let mut d2d_client_key = [0u8; 32];
        hk_d2d
            .expand(b"client", &mut d2d_client_key)
            .map_err(|e| anyhow!("HKDF expand d2d_client_key failed: {:?}", e))?;

        // KEYCHAIN_SALT = Sha256("SecureMessage")
        let mut hasher_km = Sha256::new();
        hasher_km.update(b"SecureMessage");
        let keychain_salt = hasher_km.finalize();

        // Client encryption and HMAC keys
        let hk_client = Hkdf::<Sha256>::new(Some(&keychain_salt), &d2d_client_key);
        let mut client_key = [0u8; 32];
        let mut client_hmac_key = [0u8; 32];
        hk_client
            .expand(b"ENC:2", &mut client_key)
            .map_err(|e| anyhow!("HKDF expand client_key failed: {:?}", e))?;
        hk_client
            .expand(b"SIG:1", &mut client_hmac_key)
            .map_err(|e| anyhow!("HKDF expand client_hmac_key failed: {:?}", e))?;

        // Server encryption and HMAC keys
        let hk_server = Hkdf::<Sha256>::new(Some(&keychain_salt), &d2d_server_key);
        let mut server_key = [0u8; 32];
        let mut server_hmac_key = [0u8; 32];
        hk_server
            .expand(b"ENC:2", &mut server_key)
            .map_err(|e| anyhow!("HKDF expand server_key failed: {:?}", e))?;
        hk_server
            .expand(b"SIG:1", &mut server_hmac_key)
            .map_err(|e| anyhow!("HKDF expand server_hmac_key failed: {:?}", e))?;

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

pub fn to_twos_complement(bytes: &[u8]) -> Vec<u8> {
    if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
        let mut out = Vec::with_capacity(bytes.len() + 1);
        out.push(0x00);
        out.extend_from_slice(bytes);
        out
    } else {
        bytes.to_vec()
    }
}

pub fn from_twos_complement(bytes: &[u8]) -> Result<[u8; 32]> {
    let s = if bytes.len() > 32 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    };
    if s.len() > 32 {
        return Err(anyhow!("Invalid P-256 coordinate length: {}", s.len()));
    }
    let mut out = [0u8; 32];
    out[32 - s.len()..].copy_from_slice(s);
    Ok(out)
}

pub fn encode_p256_public_key(pubkey: &PublicKey) -> Vec<u8> {
    let sec1 = pubkey.to_sec1_bytes();
    let x_bytes = &sec1[1..33];
    let y_bytes = &sec1[33..65];

    let generic_key = GenericPublicKey {
        r#type: Some(PublicKeyType::EcP256 as i32),
        ec_p256_public_key: Some(EcP256PublicKey {
            x: Some(to_twos_complement(x_bytes)),
            y: Some(to_twos_complement(y_bytes)),
        }),
    };
    let mut out = Vec::new();
    generic_key.encode(&mut out).expect("GenericPublicKey encoding failed");
    out
}

pub fn decode_p256_public_key(data: &[u8]) -> Result<PublicKey> {
    let generic_key = GenericPublicKey::decode(data)
        .map_err(|e| anyhow!("Failed to decode GenericPublicKey: {:?}", e))?;
    if generic_key.r#type() != PublicKeyType::EcP256 {
        return Err(anyhow!("Unsupported public key type: {:?}", generic_key.r#type()));
    }
    let ec_key = generic_key
        .ec_p256_public_key
        .ok_or_else(|| anyhow!("GenericPublicKey missing ec_p256_public_key"))?;
    let raw_x = ec_key.x.ok_or_else(|| anyhow!("EcP256PublicKey missing x"))?;
    let raw_y = ec_key.y.ok_or_else(|| anyhow!("EcP256PublicKey missing y"))?;

    let x_arr = from_twos_complement(&raw_x)?;
    let y_arr = from_twos_complement(&raw_y)?;

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x_arr);
    sec1[33..65].copy_from_slice(&y_arr);

    PublicKey::from_sec1_bytes(&sec1)
        .map_err(|e| anyhow!("Provided coordinates do not form a valid point on NIST P-256: {:?}", e))
}

/// Exact Quick Share 4-digit PIN derivation algorithm
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ukey2_p256_key_exchange() {
        let server_kx = Ukey2KeyExchange::new();
        let client_kx = Ukey2KeyExchange::new();

        let server_pub = server_kx.encode_public_key();
        let client_pub = client_kx.encode_public_key();

        let m1 = b"dummy_m1_bytes_for_test";
        let m2 = b"dummy_m2_bytes_for_test";

        let server_keys = server_kx
            .complete_server_exchange(&client_pub, m1, m2)
            .expect("server exchange failed");

        let client_keys = client_kx
            .complete_client_exchange(&server_pub, m1, m2)
            .expect("client exchange failed");

        assert_eq!(server_keys.client_key, client_keys.client_key);
        assert_eq!(server_keys.client_hmac_key, client_keys.client_hmac_key);
        assert_eq!(server_keys.server_key, client_keys.server_key);
        assert_eq!(server_keys.server_hmac_key, client_keys.server_hmac_key);
        assert_eq!(server_keys.auth_token, client_keys.auth_token);
        assert_eq!(server_keys.pin, client_keys.pin);
        assert_eq!(server_keys.pin.len(), 4);
    }
}

# Quick Share (Nearby Share) Wire Protocol Specification

This document provides a technical specification of the Quick Share (formerly Google Nearby Share) protocol reconstructed from static disassembly and protobuf descriptor extraction of `./data/libnearby_share.so` and `./nearby_share.exe`.

---

## 1. Protocol Architecture & Layering

The Quick Share protocol operates across four distinct abstraction layers:

```
+-------------------------------------------------------------+
| Layer 4: Application Layer (Sharing Wire Format)           |
| - IntroductionFrame (FileMetadata, TextMetadata, AppMeta)   |
| - ConnectionResponseFrame (ACCEPT / REJECT)                 |
| - PairedKeyEncryption / PairedKeyResult                     |
+-------------------------------------------------------------+
| Layer 3: Connections Framing Layer (OfflineWireFormats)     |
| - OfflineFrame (ConnectionRequest, Response, Disconnect)   |
| - PayloadTransferFrame (PayloadHeader, PayloadChunk, ACK)   |
+-------------------------------------------------------------+
| Layer 2: Transport Security Layer (UKEY2 + SecureMessage)   |
| - UKEY2 Handshake (X25519, SHA-512 commitment, HKDF)        |
| - SecureMessage (AES-256-CBC + HMAC-SHA256)                 |
| - 4-Digit Mutual Verification PIN (Modulo 9973)             |
+-------------------------------------------------------------+
| Layer 1: Transport & Discovery                             |
| - mDNS / DNS-SD Service: _FC9F5ED42C8A._tcp.local           |
| - TCP Stream: 4-byte Big-Endian Length-Prefixed Frames      |
+-------------------------------------------------------------+
```

---

## 2. Service Discovery Layer (mDNS / DNS-SD)

### 2.1 Service String Derivation
Quick Share on local Wi-Fi / LAN announces itself via DNS-SD (RFC 6763) over Multicast DNS (RFC 6762).
The service type is:
$$\text{service\_type} = \text{"\_" + SHA256("NearbySharing")[0..6].hex() + ".\_tcp"}$$

- Canonical Service ID string: `"NearbySharing"`
- Full SHA-256 Digest: `fc9f5ed42c8a5e9ec25f20f02377bcf4d1f21eb798059ffca666e1d52033c461`
- First 6 bytes (12 hex chars): `FC9F5ED42C8A`
- **Resulting mDNS Service Type:** `_FC9F5ED42C8A._tcp.local.`

### 2.2 Endpoint Information & TXT Record Format
Nearby devices advertise their presence by publishing an mDNS TXT record or service instance name containing a URL-safe Base64-encoded `WifiLanServiceInfo` binary blob.

The TXT record contains:
`n=<Base64-URL-Encoded WifiLanServiceInfo>`

#### Binary Layout of `WifiLanServiceInfo`:
| Offset | Length | Field | Description |
|---|---|---|---|
| `0x00` | 1 byte | `version_and_pcp` | `(Version << 5) \| PCP`<br>- Version 1: `(1 << 5) = 0x20`<br>- PCP 2 (`P2P_STAR`): `0x02`<br>- Value: `0x22` |
| `0x01` | 4 bytes | `endpoint_id` | 4 alphanumeric ASCII bytes randomly generated per session (e.g. `"R4X9"`) |
| `0x05` | 3 bytes | `service_id_hash` | First 3 bytes of `SHA256("NearbySharing")` = `[0xFC, 0x9F, 0x5E]` |
| `0x08` | 1 byte | `endpoint_info_length` | Length $L$ of the inner `endpoint_info` structure |
| `0x09` | $L$ bytes | `endpoint_info` | Device visibility and metadata payload (see below) |

#### Binary Layout of Inner `EndpointInfo`:
| Offset | Length | Field | Description |
|---|---|---|---|
| `0x00` | 1 byte | `header` | Bitfield:<br>- Bits 7..5: Version (0 for V1)<br>- Bit 4: Visibility (`0` = Everyone, `1` = Contacts)<br>- Bits 3..1: Device Type (`1` = Phone, `2` = Tablet, `3` = Laptop)<br>- Bit 0: Reserved / Mode (`0`) |
| `0x01` | 16 bytes | `salt / cert_key` | 16-byte random salt (or encrypted metadata key) |
| `0x11` | 1 byte | `device_name_length` | Length $N$ of UTF-8 device name |
| `0x12` | $N$ bytes | `device_name` | Human-readable name (e.g. `"Linux Receiver"`) |
| `0x12+N` | Var | `tlv_attributes` | Optional TLV tags:<br>- Type `0x02`: Length `0x01`, Capabilities |

---

## 3. Transport Layer Framing

All communication over the established TCP socket uses standard 4-byte big-endian framing:
```
+------------------------------------+--------------------------+
| Frame Length (32-bit unsigned BE) | Protobuf Payload Bytes   |
| 4 bytes                            | [Length bytes]           |
+------------------------------------+--------------------------+
```
Every message sent or received must be prefixed with its serialized length.

---

## 4. Cryptographic Handshake (UKEY2)

UKEY2 (Universal Key Exchange v2) performs mutual authentication and derives authenticated symmetric session keys over an unauthenticated byte channel.

### 4.1 Handshake Flow
```
Client (Sender)                               Server (Linux Receiver)
       |                                                 |
       |  1. OfflineFrame (ConnectionRequest)            |  (Unencrypted)
       |------------------------------------------------>|
       |                                                 |
       |  2. Ukey2Message (CLIENT_INIT)                  |  (Raw UKEY2)
       |------------------------------------------------>|
       |                                                 |
       |  3. Ukey2Message (SERVER_INIT)                  |
       |<------------------------------------------------|
       |                                                 |
       |  4. Ukey2Message (CLIENT_FINISH)                |
       |------------------------------------------------>|
       |                                                 |
       |  [Keys & PIN Derived; Encrypted Channel Open]   |
       |                                                 |
       |  5. OfflineFrame (ConnectionResponse: ACCEPT)   |  (Encrypted SecureMessage)
       |<------------------------------------------------|
```

1. **Client Init (`Ukey2ClientInit`)**:
   - `version = 1`
   - `random`: 32 cryptographically secure random bytes
   - `cipher_commitments`:
     - `handshake_cipher`: `CURVE25519_SHA512` (enum 200)
     - `commitment`: $\text{SHA-512}(\text{serialized } \text{Ukey2ClientFinished})$
   - `next_protocol`: `"AES_256_CBC-HMAC_SHA256"`

2. **Server Init (`Ukey2ServerInit`)**:
   - `version = 1`
   - `random`: 32 cryptographically secure random bytes
   - `handshake_cipher`: `CURVE25519_SHA512` (200)
   - `public_key`: 32-byte X25519 server ephemeral public key

3. **Client Finish (`Ukey2ClientFinished`)**:
   - `public_key`: 32-byte X25519 client ephemeral public key
   - Server verifies: $\text{SHA-512}(\text{serialized } \text{ClientFinished}) == \text{commitment}$

### 4.2 Key Derivation Pipeline
1. **Diffie-Hellman Exchange**:
   $$\text{shared\_secret} = \text{X25519}(\text{server\_private\_key}, \text{client\_public\_key}) \quad (32 \text{ bytes})$$

2. **Handshake PRK (Pseudo-Random Key)**:
   $$\text{PRK} = \text{HKDF-Extract}(\text{salt}=\text{client\_random} \parallel \text{server\_random}, \text{IKM}=\text{shared\_secret})$$

3. **Authentication Token**:
   $$\text{auth\_token} = \text{HKDF-Expand}(\text{PRK}, \text{info}=\text{"UKEY2 v1 auth"}, \text{len}=32)$$

4. **Next Protocol Secret**:
   $$\text{next\_secret} = \text{HKDF-Expand}(\text{PRK}, \text{info}=\text{"UKEY2 v1 next"}, \text{len}=32)$$

5. **Session Encryption Keys**:
   Using `HKDF-Expand` with `next_secret` and info strings:
   - `client_key` (32 bytes AES-256 key for client-to-server traffic)
   - `client_hmac_key` (32 bytes HMAC-SHA256 key for client-to-server traffic)
   - `server_key` (32 bytes AES-256 key for server-to-client traffic)
   - `server_hmac_key` (32 bytes HMAC-SHA256 key for server-to-client traffic)

### 4.3 4-Digit Mutual Verification PIN Algorithm
Reversed from `nearby_share.exe` at address `0x1404E2160`:
```rust
fn compute_verification_pin(auth_token: &[u8]) -> String {
    let mut hash: i32 = 0;
    let mut multiplier: i32 = 1;

    for &byte in auth_token {
        let signed_byte = byte as i8 as i32;
        hash = (hash + signed_byte * multiplier) % 9973;
        multiplier = (multiplier * 31) % 9973;
    }

    format!("{:04}", hash.abs())
}
```
Both devices compute and display this identical 4-digit code to allow users to visually verify the connection before accepting files.

---

## 5. Post-Handshake Framing & Encryption

After the UKEY2 handshake completes, all frames are encapsulated in `SecureMessage`:
```protobuf
message SecureMessage {
  optional bytes header_and_body = 1;
  optional bytes signature = 2; // HMAC-SHA256(header_and_body)
}

message HeaderAndBody {
  optional Header header = 1;
  optional bytes body = 2;     // AES-256-CBC Encrypted Ciphertext
}
```

When decrypted, the body deserializes to `DeviceToDeviceMessage`:
```protobuf
message DeviceToDeviceMessage {
  optional bytes message = 1;         // Serialized OfflineFrame
  optional int32 sequence_number = 2; // Incremental sequence (0, 1, 2...)
}
```

---

## 6. Transfer State Machine & Payload Delivery

```
Client (Sender)                               Server (Linux Receiver)
       |                                                 |
       |  1. OfflineFrame(CONNECTION_REQUEST)            |
       |------------------------------------------------>|
       |                                                 |
       |  2. OfflineFrame(CONNECTION_RESPONSE: ACCEPT)   |
       |<------------------------------------------------|
       |                                                 |
       |  3. OfflineFrame(PAIRED_KEY_ENCRYPTION)         |
       |------------------------------------------------>|
       |                                                 |
       |  4. OfflineFrame(PAIRED_KEY_RESULT: SUCCESS)    |
       |<------------------------------------------------|
       |                                                 |
       |  5. PayloadTransferFrame(BYTES: Introduction)   |
       |     [Contains FileMetadata: name, size, mime]   |
       |------------------------------------------------>|
       |                                                 |
       |  6. PayloadTransferFrame(BYTES: Accept Transfer)|
       |     [ConnectionResponseFrame: ACCEPT]           |
       |<------------------------------------------------|
       |                                                 |
       |  7. PayloadTransferFrame(DATA chunks...)        |
       |     [flags: 0, body: file chunk 1]              |
       |------------------------------------------------>|
       |     [flags: 0, body: file chunk 2]              |
       |------------------------------------------------>|
       |     [flags: 1 (LAST_CHUNK), body: file chunk N] |
       |------------------------------------------------>|
       |                                                 |
       |  8. PayloadTransferFrame(CONTROL: ACK)          |
       |<------------------------------------------------|
```

### 6.1 Introduction Frame Structure
The transfer metadata is conveyed in a `SharingFrame` containing an `IntroductionFrame`:
- `file_metadata`:
  - `name`: Target filename (e.g. `"vacation.jpg"`)
  - `size`: Total file size in bytes (int64)
  - `mime_type`: MIME descriptor (e.g. `"image/jpeg"`)
  - `payload_id`: Matching payload identifier in subsequent `PayloadTransferFrame` headers.

### 6.2 Chunked File Ingestion
File chunks arrive via `PayloadTransferFrame`:
- `packet_type = DATA (1)`
- `payload_header`: Contains `id` matching `payload_id`, `type = FILE (2)`, `total_size`
- `payload_chunk`:
  - `flags`: `LAST_CHUNK (1)` indicates EOF
  - `offset`: byte offset within target file
  - `body`: raw file payload bytes

The receiver continuously streams chunks to a disk file located in `~/Downloads/`. When `flags == LAST_CHUNK`, the file descriptor is synced, closed, and an acknowledgement frame is returned.

use crate::crypto::SessionKeys;
use crate::events::AppEvent;
use crate::proto::wire::{
    connection_response_frame::ResponseStatus,
    connections_v1_frame::FrameType as ConnectionsFrameType,
    paired_key_result_frame::Status as PairedKeyStatus,
    payload_transfer_frame::{
        payload_header::PayloadType, PayloadChunk, PayloadHeader,
    },
    payload_transfer_frame::PacketType,
    sharing_response_frame::Status as SharingResponseStatus,
    sharing_v1_frame::FrameType as SharingFrameType,
    ConnectionRequestFrame, ConnectionsPairedKeyEncryptionFrame, ConnectionsV1Frame,
    FileMetadata, IntroductionFrame, OfflineFrame, PairedKeyResultFrame, PayloadTransferFrame,
    SharingFrame, SharingV1Frame,
};
use crate::secure_frame::{decrypt_secure_frame, encrypt_secure_frame, ProtocolRole};
use crate::transport::{read_length_prefixed_frame, write_length_prefixed_frame};
use crate::ukey2::perform_ukey2_handshake_client;
use anyhow::{anyhow, Result};
use tokio::sync::mpsc::UnboundedSender;
use prost::Message;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub struct QuickShareSender {
    peer_ip: IpAddr,
    peer_port: u16,
    my_endpoint_id: String,
    my_device_name: String,
    files: Vec<PathBuf>,
    ui_sender: Option<UnboundedSender<AppEvent>>,
}

impl QuickShareSender {
    pub fn new(
        peer_ip: IpAddr,
        peer_port: u16,
        my_endpoint_id: String,
        my_device_name: String,
        files: Vec<PathBuf>,
        ui_sender: Option<UnboundedSender<AppEvent>>,
    ) -> Self {
        Self {
            peer_ip,
            peer_port,
            my_endpoint_id,
            my_device_name,
            files,
            ui_sender,
        }
    }

    pub async fn run(self) -> Result<()> {
        let addr = format!("{}:{}", self.peer_ip, self.peer_port);
        info!("Connecting to Quick Share peer at {}", addr);

        let mut stream = TcpStream::connect((self.peer_ip, self.peer_port))
            .await
            .map_err(|e| anyhow!("Failed to connect to peer {}: {:?}", addr, e))?;

        // 1. UKEY2 Handshake as Client
        let keys = perform_ukey2_handshake_client(&mut stream).await?;
        info!("UKEY2 Handshake finished. Verification PIN: [{}]", keys.pin);

        if let Some(ref tx) = self.ui_sender {
            let _ = tx.send(AppEvent::StatusNotification(format!(
                "Connected to peer. Verification PIN: {}",
                keys.pin
            )));
        }

        let mut seq = 0i32;

        // 2. Send ConnectionRequest
        let conn_req = ConnectionRequestFrame {
            endpoint_id: Some(self.my_endpoint_id.clone()),
            endpoint_name: Some(self.my_device_name.clone()),
            handshake_data: None,
            nonce: None,
            mediums: vec![5], // WifiLan
            endpoint_info: Some(self.my_device_name.as_bytes().to_vec()),
            keep_alive_interval_millis: None,
            keep_alive_timeout_millis: Some(5000),
            device_type: Some(1), // Phone/Laptop
            device_info: None,
            connection_mode: None,
        };
        let offline_req = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::ConnectionRequest as i32),
                connection_request: Some(conn_req),
                connection_response: None,
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        send_frame(&mut stream, &keys, &offline_req, &mut seq).await?;
        debug!("Sent ConnectionRequest");

        // 3. Receive ConnectionResponse
        let (resp_frame, _) = read_frame(&mut stream, &keys).await?;
        let v1 = resp_frame
            .v1
            .ok_or_else(|| anyhow!("ConnectionResponse missing v1 frame"))?;
        if v1.r#type() != ConnectionsFrameType::ConnectionResponse {
            return Err(anyhow!("Expected ConnectionResponse, got {:?}", v1.r#type()));
        }
        let conn_resp = v1
            .connection_response
            .ok_or_else(|| anyhow!("Missing connection_response in frame"))?;
        if conn_resp.status != Some(ResponseStatus::Accept as i32) {
            return Err(anyhow!(
                "Connection rejected by peer: status {:?}",
                conn_resp.status
            ));
        }
        info!("Peer accepted connection request");

        // 4. Send PairedKeyEncryption
        let paired_key_result = PairedKeyResultFrame {
            status: Some(PairedKeyStatus::Success as i32),
            os_type: Some(1), // Linux
        };
        let mut signed_data = Vec::new();
        paired_key_result.encode(&mut signed_data)?;

        let enc_frame = ConnectionsPairedKeyEncryptionFrame {
            signed_data: Some(signed_data),
            secret_id_hash: None,
            optional_signed_data: None,
        };
        let offline_enc = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PairedKeyEncryption as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: Some(enc_frame),
                authentication_message: None,
                authentication_result: None,
            }),
        };
        send_frame(&mut stream, &keys, &offline_enc, &mut seq).await?;
        debug!("Sent PairedKeyEncryption");

        // 5. Receive peer PairedKeyEncryption result
        let (peer_enc_frame, _) = read_frame(&mut stream, &keys).await?;
        let p_v1 = peer_enc_frame.v1.ok_or_else(|| anyhow!("Missing v1 in PairedKey response"))?;
        if p_v1.r#type() != ConnectionsFrameType::PairedKeyEncryption {
            warn!("Unexpected response after PairedKeyEncryption: {:?}", p_v1.r#type());
        }

        // 6. Build IntroductionFrame with file metadata
        let mut file_metas = Vec::new();
        let mut file_payloads = Vec::new();

        for path in &self.files {
            let meta = tokio::fs::metadata(path)
                .await
                .map_err(|e| anyhow!("Failed to read metadata for {:?}: {:?}", path, e))?;
            let size = meta.len() as i64;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "file.bin".to_string());
            let mime = guess_mime_type(&name);
            let payload_id = rand::random::<i64>().abs();

            file_metas.push(FileMetadata {
                name: Some(name.clone()),
                r#type: Some(1), // File
                payload_id: Some(payload_id),
                size: Some(size),
                mime_type: Some(mime),
                id: Some(rand::random::<i64>().abs()),
                parent_folder: None,
                attachment_hash: None,
                is_sensitive_content: None,
            });
            file_payloads.push((path.clone(), name, size as u64, payload_id));
        }

        let intro_frame = IntroductionFrame {
            file_metadata: file_metas,
            text_metadata: Vec::new(),
            required_package: None,
            wifi_credentials_metadata: Vec::new(),
            app_metadata: Vec::new(),
            start_transfer: Some(true),
            stream_metadata: Vec::new(),
            use_case: None,
            preview_payload_ids: Vec::new(),
            transfer_id: None,
        };
        let sharing_frame = SharingFrame {
            version: Some(1),
            v1: Some(SharingV1Frame {
                r#type: Some(SharingFrameType::Introduction as i32),
                introduction: Some(intro_frame),
                connection_response: None,
                paired_key_encryption: None,
                paired_key_result: None,
                certificate_info: None,
                progress_update: None,
            }),
        };
        let mut intro_bytes = Vec::new();
        sharing_frame.encode(&mut intro_bytes)?;

        // Send Introduction wrapped in PayloadTransfer (Bytes)
        let payload_frame = PayloadTransferFrame {
            packet_type: Some(PacketType::Data as i32),
            payload_header: Some(PayloadHeader {
                id: Some(rand::random::<i64>().abs()),
                r#type: Some(PayloadType::Bytes as i32),
                total_size: Some(intro_bytes.len() as i64),
                is_sensitive: None,
                file_name: None,
                parent_folder: None,
                last_modified_timestamp_millis: None,
            }),
            payload_chunk: Some(PayloadChunk {
                flags: Some(1), // LAST_CHUNK
                offset: Some(0),
                body: Some(intro_bytes),
                index: Some(0),
            }),
            control_message: None,
        };
        let offline_intro = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: Some(payload_frame),
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        send_frame(&mut stream, &keys, &offline_intro, &mut seq).await?;
        info!("Sent IntroductionFrame for {} files", file_payloads.len());

        // 7. Receive peer SharingResponseFrame
        let (sharing_resp_frame, _) = read_frame(&mut stream, &keys).await?;
        let s_v1 = sharing_resp_frame.v1.ok_or_else(|| anyhow!("Missing v1 in sharing response"))?;
        let payload_transfer = s_v1.payload_transfer.ok_or_else(|| anyhow!("Missing payload_transfer in sharing response"))?;
        let chunk = payload_transfer.payload_chunk.ok_or_else(|| anyhow!("Missing chunk in sharing response"))?;
        let body = chunk.body.ok_or_else(|| anyhow!("Missing body in sharing response"))?;

        let decoded_sharing = SharingFrame::decode(&body[..])
            .map_err(|e| anyhow!("Failed to decode SharingFrame: {:?}", e))?;
        let sh_v1 = decoded_sharing.v1.ok_or_else(|| anyhow!("Missing v1 in decoded SharingFrame"))?;
        let resp = sh_v1.connection_response.ok_or_else(|| anyhow!("Missing connection_response in SharingFrame"))?;

        if resp.status != Some(SharingResponseStatus::Accept as i32) {
            let err_msg = format!("Transfer declined by recipient (status: {:?})", resp.status);
            if let Some(ref tx) = self.ui_sender {
                let _ = tx.send(AppEvent::StatusNotification(err_msg.clone()));
            }
            return Err(anyhow!("{}", err_msg));
        }

        info!("Recipient accepted transfer! Beginning payload streaming...");

        // 8. Stream file payloads
        const CHUNK_SIZE: usize = 65536; // 64 KB chunks
        let mut buffer = vec![0u8; CHUNK_SIZE];

        for (path, name, total_size, payload_id) in file_payloads {
            if let Some(ref tx) = self.ui_sender {
                let _ = tx.send(AppEvent::TransferStarted {
                    transfer_id: payload_id as u64,
                    filename: name.clone(),
                    total: total_size,
                    is_send: true,
                });
            }

            let mut file = tokio::fs::File::open(&path)
                .await
                .map_err(|e| anyhow!("Failed to open file {:?}: {:?}", path, e))?;

            let mut offset = 0u64;
            let mut chunk_index = 0i32;
            let start_time = Instant::now();

            loop {
                let bytes_read = file
                    .read(&mut buffer)
                    .await
                    .map_err(|e| anyhow!("Error reading from file {:?}: {:?}", path, e))?;

                if bytes_read == 0 && offset > 0 {
                    break;
                }

                let is_last = (offset + bytes_read as u64) >= total_size || bytes_read == 0;
                let flags = if is_last { 1 } else { 0 };

                let chunk_frame = PayloadTransferFrame {
                    packet_type: Some(PacketType::Data as i32),
                    payload_header: Some(PayloadHeader {
                        id: Some(payload_id),
                        r#type: Some(PayloadType::File as i32),
                        total_size: Some(total_size as i64),
                        is_sensitive: None,
                        file_name: Some(name.clone()),
                        parent_folder: None,
                        last_modified_timestamp_millis: None,
                    }),
                    payload_chunk: Some(PayloadChunk {
                        flags: Some(flags),
                        offset: Some(offset as i64),
                        body: Some(buffer[..bytes_read].to_vec()),
                        index: Some(chunk_index),
                    }),
                    control_message: None,
                };

                let offline_chunk = OfflineFrame {
                    version: Some(1),
                    v1: Some(ConnectionsV1Frame {
                        r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                        connection_request: None,
                        connection_response: None,
                        payload_transfer: Some(chunk_frame),
                        bandwidth_upgrade_negotiation: None,
                        keep_alive: None,
                        disconnection: None,
                        paired_key_encryption: None,
                        authentication_message: None,
                        authentication_result: None,
                    }),
                };

                send_frame(&mut stream, &keys, &offline_chunk, &mut seq).await?;

                offset += bytes_read as u64;
                chunk_index += 1;

                let elapsed_secs = start_time.elapsed().as_secs_f64();
                let speed_mbps = if elapsed_secs > 0.05 {
                    (offset as f64 / 1_048_576.0) / elapsed_secs
                } else {
                    0.0
                };

                if let Some(ref tx) = self.ui_sender {
                    let _ = tx.send(AppEvent::TransferProgress {
                        transfer_id: payload_id as u64,
                        filename: name.clone(),
                        transferred: offset,
                        total: total_size,
                        speed_mbps,
                        is_send: true,
                    });
                }

                if is_last {
                    break;
                }
            }

            if let Some(ref tx) = self.ui_sender {
                let _ = tx.send(AppEvent::TransferCompleted {
                    transfer_id: payload_id as u64,
                    filename: name.clone(),
                    is_send: true,
                });
            }
            info!("File '{}' transmitted successfully!", name);
        }

        // Clean disconnection
        let disconnect_frame = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::Disconnection as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let _ = send_frame(&mut stream, &keys, &disconnect_frame, &mut seq).await;
        info!("All files sent! Transfer session finished successfully.");
        Ok(())
    }
}

async fn send_frame(
    stream: &mut TcpStream,
    keys: &SessionKeys,
    frame: &OfflineFrame,
    seq: &mut i32,
) -> Result<()> {
    let encrypted = encrypt_secure_frame(keys, frame, *seq, ProtocolRole::Client)?;
    *seq += 1;
    write_length_prefixed_frame(stream, &encrypted).await?;
    Ok(())
}

async fn read_frame(
    stream: &mut TcpStream,
    keys: &SessionKeys,
) -> Result<(OfflineFrame, i32)> {
    let raw = read_length_prefixed_frame(stream).await?;
    decrypt_secure_frame(keys, &raw, ProtocolRole::Client)
}

fn guess_mime_type(filename: &str) -> String {
    let lower = filename.to_lowercase();
    if lower.ends_with(".png") {
        "image/png".to_string()
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg".to_string()
    } else if lower.ends_with(".gif") {
        "image/gif".to_string()
    } else if lower.ends_with(".webp") {
        "image/webp".to_string()
    } else if lower.ends_with(".mp4") {
        "video/mp4".to_string()
    } else if lower.ends_with(".pdf") {
        "application/pdf".to_string()
    } else if lower.ends_with(".txt") {
        "text/plain".to_string()
    } else if lower.ends_with(".zip") {
        "application/zip".to_string()
    } else if lower.ends_with(".tar.gz") {
        "application/gzip".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

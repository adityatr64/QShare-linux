use crate::crypto::SessionKeys;
use crate::events::AppEvent;
use crate::proto::wire::{
    connection_response_frame::ResponseStatus,
    connections_v1_frame::FrameType as ConnectionsFrameType,
    paired_key_result_frame::Status as PairedKeyStatus,
    payload_transfer_frame::{
        control_message::EventType as ControlEventType, payload_header::PayloadType,
        PacketType, PayloadChunk, PayloadHeader,
    },
    sharing_response_frame::Status as SharingResponseStatus,
    sharing_v1_frame::FrameType as SharingFrameType,
    ConnectionRequestFrame, ConnectionResponseFrame, ConnectionsV1Frame,
    DisconnectionFrame, FileMetadata, IntroductionFrame, KeepAliveFrame, OfflineFrame,
    PairedKeyEncryptionFrame, PairedKeyResultFrame, PayloadTransferFrame, SharingFrame,
    SharingV1Frame,
};
use crate::secure_frame::{decrypt_secure_frame, encrypt_secure_frame, ProtocolRole};
use crate::transport::{read_length_prefixed_frame, write_length_prefixed_frame};
use crate::ukey2::perform_ukey2_handshake_client;
use anyhow::{anyhow, Result};
use rand::{rngs::OsRng, RngCore};
use tokio::sync::mpsc::UnboundedSender;
use prost::Message;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

        // 1. Send unencrypted ConnectionRequest as Client
        let dev_bytes = self.my_device_name.as_bytes();
        let dev_len = dev_bytes.len().min(32) as u8;
        let mut endpoint_info_bytes = Vec::with_capacity(1 + 16 + 1 + dev_len as usize);
        endpoint_info_bytes.push(0x06u8); // V1, visible to everyone, Laptop device type (3 << 1)
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        endpoint_info_bytes.extend_from_slice(&salt);
        endpoint_info_bytes.push(dev_len);
        endpoint_info_bytes.extend_from_slice(&dev_bytes[..dev_len as usize]);

        let conn_req = ConnectionRequestFrame {
            endpoint_id: Some(self.my_endpoint_id.clone()),
            endpoint_name: Some(self.my_device_name.clone()),
            handshake_data: None,
            nonce: Some(rand::random::<i32>().abs()),
            mediums: vec![1, 5], // MDNS, WifiLan
            endpoint_info: Some(endpoint_info_bytes),
            keep_alive_interval_millis: Some(5000),
            keep_alive_timeout_millis: Some(30000),
            device_type: Some(3), // Laptop
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
        let mut raw_bytes = Vec::new();
        offline_req.encode(&mut raw_bytes)?;
        write_length_prefixed_frame(&mut stream, &raw_bytes).await?;
        debug!("Sent unencrypted ConnectionRequest");

        // 2. UKEY2 Handshake as Client
        let keys = perform_ukey2_handshake_client(&mut stream).await?;
        info!("UKEY2 Handshake finished. Verification PIN: [{}]", keys.pin);

        if let Some(ref tx) = self.ui_sender {
            let _ = tx.send(AppEvent::StatusNotification(format!(
                "Connected to peer. Verification PIN: {}",
                keys.pin
            )));
        }

        let mut seq = 1i32;

        // 3. Send unencrypted ConnectionResponse (Client -> Server)
        let my_resp = ConnectionResponseFrame {
            status: Some(ResponseStatus::Accept as i32),
            handshake_data: None,
            response: Some(ResponseStatus::Accept as i32),
            os_info: Some(crate::proto::wire::OsInfo {
                r#type: Some(crate::proto::wire::os_info::OsType::Linux as i32),
            }),
            multiplex_socket_bitmask: Some(0),
            nearby_connections_version: Some(1),
            safe_to_disconnect_version: None,
            keep_alive_timeout_millis: Some(5000),
            wifi_direct_device_name: None,
        };
        let my_resp_offline = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::ConnectionResponse as i32),
                connection_request: None,
                connection_response: Some(my_resp),
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let mut raw_my_resp = Vec::new();
        my_resp_offline.encode(&mut raw_my_resp)?;
        write_length_prefixed_frame(&mut stream, &raw_my_resp).await?;
        debug!("Sent unencrypted ConnectionResponse");

        // 4. Receive unencrypted ConnectionResponse (Server -> Client)
        let raw_server_resp = read_length_prefixed_frame(&mut stream).await?;
        let resp_frame = OfflineFrame::decode(raw_server_resp.as_slice())
            .map_err(|e| anyhow!("Failed to decode unencrypted ConnectionResponse: {:?}", e))?;
        let v1 = resp_frame
            .v1
            .ok_or_else(|| anyhow!("ConnectionResponse missing v1 frame"))?;
        if v1.r#type() != ConnectionsFrameType::ConnectionResponse {
            return Err(anyhow!("Expected ConnectionResponse, got {:?}", v1.r#type()));
        }
        let conn_resp = v1
            .connection_response
            .ok_or_else(|| anyhow!("Missing connection_response in frame"))?;
        let is_accepted = conn_resp.status == Some(ResponseStatus::Accept as i32)
            || conn_resp.response == Some(ResponseStatus::Accept as i32)
            || conn_resp.status == Some(0);
        if !is_accepted {
            return Err(anyhow!(
                "Connection rejected by peer: status {:?}, response {:?}",
                conn_resp.status,
                conn_resp.response
            ));
        }
        info!("Peer accepted connection request");

        // 4. Send PairedKeyEncryption SharingFrame
        let sharing_enc = SharingFrame {
            version: Some(1),
            v1: Some(SharingV1Frame {
                r#type: Some(SharingFrameType::PairedKeyEncryption as i32),
                introduction: None,
                connection_response: None,
                paired_key_encryption: Some(PairedKeyEncryptionFrame {
                    secret_id_hash: Some((0..6).map(|_| rand::random::<u8>()).collect()),
                    signed_data: Some((0..72).map(|_| rand::random::<u8>()).collect()),
                    optional_signed_data: None,
                    qr_code_handshake_data: None,
                }),
                paired_key_result: None,
                certificate_info: None,
                progress_update: None,
            }),
        };
        send_sharing_frame(&mut stream, &keys, &sharing_enc, &mut seq).await?;
        debug!("Sent SharingFrame PairedKeyEncryption");

        // 5. Receive peer PairedKey responses and complete the exchange
        let mut sent_our_result = false;
        let mut received_peer_result = false;
        let mut bytes_buffers: std::collections::HashMap<i64, Vec<u8>> = std::collections::HashMap::new();

        for round in 0..10 {
            let frame_res = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read_next_sharing_frame(&mut stream, &keys, &mut seq, &mut bytes_buffers)
            ).await;

            match frame_res {
                Ok(Ok(sf)) => {
                    if let Some(ref v1) = sf.v1 {
                        match v1.r#type() {
                            SharingFrameType::PairedKeyEncryption => {
                                info!("Received peer's SharingFrame PairedKeyEncryption");
                                if !sent_our_result {
                                    let result_frame = SharingFrame {
                                        version: Some(1),
                                        v1: Some(SharingV1Frame {
                                            r#type: Some(SharingFrameType::PairedKeyResult as i32),
                                            introduction: None,
                                            connection_response: None,
                                            paired_key_encryption: None,
                                            paired_key_result: Some(PairedKeyResultFrame {
                                                status: Some(PairedKeyStatus::Unable as i32),
                                                os_type: Some(crate::proto::wire::os_info::OsType::Linux as i32),
                                            }),
                                            certificate_info: None,
                                            progress_update: None,
                                        }),
                                    };
                                    send_sharing_frame(&mut stream, &keys, &result_frame, &mut seq).await?;
                                    info!("Sent SharingFrame PairedKeyResult (UNABLE)");
                                    sent_our_result = true;
                                }
                            }
                            SharingFrameType::PairedKeyResult => {
                                info!("Received peer's SharingFrame PairedKeyResult");
                                received_peer_result = true;
                                if !sent_our_result {
                                    let result_frame = SharingFrame {
                                        version: Some(1),
                                        v1: Some(SharingV1Frame {
                                            r#type: Some(SharingFrameType::PairedKeyResult as i32),
                                            introduction: None,
                                            connection_response: None,
                                            paired_key_encryption: None,
                                            paired_key_result: Some(PairedKeyResultFrame {
                                                status: Some(PairedKeyStatus::Unable as i32),
                                                os_type: Some(crate::proto::wire::os_info::OsType::Linux as i32),
                                            }),
                                            certificate_info: None,
                                            progress_update: None,
                                        }),
                                    };
                                    send_sharing_frame(&mut stream, &keys, &result_frame, &mut seq).await?;
                                    info!("Sent SharingFrame PairedKeyResult (UNABLE)");
                                    sent_our_result = true;
                                }
                            }
                            other => {
                                debug!("Received SharingFrame type {:?} during paired key exchange", other);
                            }
                        }
                    }
                    if sent_our_result && received_peer_result {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    warn!("Error reading during paired key exchange: {:?}", e);
                    return Err(e);
                }
                Err(_) => {
                    debug!("Timeout waiting for paired key frame round {}", round);
                    if sent_our_result {
                        break;
                    }
                }
            }
        }

        if !sent_our_result {
            let result_frame = SharingFrame {
                version: Some(1),
                v1: Some(SharingV1Frame {
                    r#type: Some(SharingFrameType::PairedKeyResult as i32),
                    introduction: None,
                    connection_response: None,
                    paired_key_encryption: None,
                    paired_key_result: Some(PairedKeyResultFrame {
                        status: Some(PairedKeyStatus::Unable as i32),
                        os_type: Some(crate::proto::wire::os_info::OsType::Linux as i32),
                    }),
                    certificate_info: None,
                    progress_update: None,
                }),
            };
            send_sharing_frame(&mut stream, &keys, &result_frame, &mut seq).await?;
            info!("Sent SharingFrame PairedKeyResult (UNABLE) [proactive]");
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
            let file_type = file_type_from_mime(&mime);
            let payload_id = rand::random::<i64>().abs();

            file_metas.push(FileMetadata {
                name: Some(name.clone()),
                r#type: Some(file_type),
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
            use_case: Some(1), // NEARBY_SHARE = 1
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
        send_sharing_frame(&mut stream, &keys, &sharing_frame, &mut seq).await?;
        info!("Sent IntroductionFrame for {} files", file_payloads.len());

        if let Some(ref tx) = self.ui_sender {
            let _ = tx.send(AppEvent::StatusNotification(
                "Waiting for recipient to accept on their device...".to_string()
            ));
        }

        // 7. Receive peer SharingResponseFrame (wait up to 60s for user acceptance)
        let decoded_sharing = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            read_next_sharing_frame(&mut stream, &keys, &mut seq, &mut bytes_buffers)
        )
        .await
        .map_err(|_| anyhow!("Timed out waiting for recipient to accept transfer"))??;

        let sh_v1 = decoded_sharing.v1.ok_or_else(|| anyhow!("Missing v1 in decoded SharingFrame"))?;
        let resp = sh_v1.connection_response.ok_or_else(|| anyhow!("Missing connection_response in SharingFrame (got {:?})", sh_v1.r#type()))?;

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

        for (path, name, total_size, payload_id) in &file_payloads {
            let total_size = *total_size;
            let payload_id = *payload_id;

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

                if bytes_read == 0 {
                    break;
                }

                // Data chunk: flags MUST be 0 (data only)
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
                        flags: Some(0), // Data chunk flags = 0
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
            }

            // Dedicated terminator frame (empty body, flags = LAST_CHUNK = 1)
            // Required by Android & Samsung One UI 7+ (Two-Frame requirement)
            let terminator_frame = PayloadTransferFrame {
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
                    flags: Some(1), // LAST_CHUNK
                    offset: Some(total_size as i64),
                    body: Some(Vec::new()),
                    index: Some(chunk_index),
                }),
                control_message: None,
            };

            let offline_terminator = OfflineFrame {
                version: Some(1),
                v1: Some(ConnectionsV1Frame {
                    r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                    connection_request: None,
                    connection_response: None,
                    payload_transfer: Some(terminator_frame),
                    bandwidth_upgrade_negotiation: None,
                    keep_alive: None,
                    disconnection: None,
                    paired_key_encryption: None,
                    authentication_message: None,
                    authentication_result: None,
                }),
            };

            send_frame(&mut stream, &keys, &offline_terminator, &mut seq).await?;
            info!(
                "File '{}' data chunks & LAST_CHUNK terminator transmitted (total: {} bytes)",
                name, total_size
            );
        }

        stream.flush().await?;

        // 9. Send safe-to-disconnect request
        let disconnect_frame = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::Disconnection as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: Some(DisconnectionFrame {
                    request_safe_to_disconnect: Some(true),
                    ack_safe_to_disconnect: None,
                }),
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let _ = send_frame(&mut stream, &keys, &disconnect_frame, &mut seq).await;
        let _ = stream.flush().await;

        info!("Waiting for recipient acknowledgement and safe disconnect...");
        let wait_deadline = Instant::now() + std::time::Duration::from_secs(15);
        let acks_needed = file_payloads.len();
        let mut acks_received = 0;

        while Instant::now() < wait_deadline {
            let remaining = wait_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, read_frame(&mut stream, &keys)).await {
                Ok(Ok((frame, _))) => {
                    if let Some(v1) = frame.v1 {
                        match v1.r#type() {
                            ConnectionsFrameType::Disconnection => {
                                info!("Received Disconnection confirmation from recipient.");
                                break;
                            }
                            ConnectionsFrameType::KeepAlive => {
                                debug!("Replied to recipient KeepAlive with ACK during completion wait");
                                let keep_alive_ack = OfflineFrame {
                                    version: Some(1),
                                    v1: Some(ConnectionsV1Frame {
                                        r#type: Some(ConnectionsFrameType::KeepAlive as i32),
                                        connection_request: None,
                                        connection_response: None,
                                        payload_transfer: None,
                                        bandwidth_upgrade_negotiation: None,
                                        keep_alive: Some(KeepAliveFrame { ack: Some(true) }),
                                        disconnection: None,
                                        paired_key_encryption: None,
                                        authentication_message: None,
                                        authentication_result: None,
                                    }),
                                };
                                let _ = send_frame(&mut stream, &keys, &keep_alive_ack, &mut seq).await;
                            }
                            ConnectionsFrameType::PayloadTransfer => {
                                if let Some(pt) = v1.payload_transfer {
                                    if pt.packet_type() == PacketType::Control {
                                        if let Some(ctrl) = pt.control_message {
                                            if ctrl.event() == ControlEventType::PayloadReceivedAck {
                                                acks_received += 1;
                                                info!(
                                                    "Recipient acknowledged file receipt (PAYLOAD_RECEIVED_ACK, offset: {:?}) [{}/{}]",
                                                    ctrl.offset, acks_received, acks_needed
                                                );
                                                if acks_received >= acks_needed {
                                                    // Give recipient 500ms grace period to cleanly close socket
                                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Err(e)) => {
                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                        if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                            info!("Recipient closed connection cleanly after receiving payload.");
                            break;
                        }
                    }
                    debug!("Peer closed or errored during completion wait: {:?}", e);
                    break;
                }
                Err(_) => {
                    info!("Safe disconnect wait timeout reached.");
                    break;
                }
            }
        }

        // Notify UI that transfers completed successfully
        for (path, name, _, payload_id) in &file_payloads {
            if let Some(ref tx) = self.ui_sender {
                let _ = tx.send(AppEvent::TransferCompleted {
                    transfer_id: *payload_id as u64,
                    filename: name.clone(),
                    file_path: Some(path.clone()),
                    is_send: true,
                });
            }
            info!("File '{}' transmitted successfully!", name);
        }

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

async fn send_sharing_frame(
    stream: &mut TcpStream,
    keys: &SessionKeys,
    sharing: &SharingFrame,
    seq: &mut i32,
) -> Result<()> {
    let mut sharing_bytes = Vec::new();
    sharing.encode(&mut sharing_bytes)?;

    let payload_id = rand::random::<i64>().abs();

    // 1. Initial chunk: flags=0, offset=0, body=sharing_bytes
    let chunk1 = PayloadTransferFrame {
        packet_type: Some(PacketType::Data as i32),
        payload_header: Some(PayloadHeader {
            id: Some(payload_id),
            r#type: Some(PayloadType::Bytes as i32),
            total_size: Some(sharing_bytes.len() as i64),
            is_sensitive: Some(false),
            file_name: None,
            parent_folder: None,
            last_modified_timestamp_millis: None,
        }),
        payload_chunk: Some(PayloadChunk {
            flags: Some(0),
            offset: Some(0),
            body: Some(sharing_bytes.clone()),
            index: Some(0),
        }),
        control_message: None,
    };

    let offline_chunk1 = OfflineFrame {
        version: Some(1),
        v1: Some(ConnectionsV1Frame {
            r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
            connection_request: None,
            connection_response: None,
            payload_transfer: Some(chunk1),
            bandwidth_upgrade_negotiation: None,
            keep_alive: None,
            disconnection: None,
            paired_key_encryption: None,
            authentication_message: None,
            authentication_result: None,
        }),
    };
    send_frame(stream, keys, &offline_chunk1, seq).await?;

    // 2. Terminal chunk: flags=1 (LAST_CHUNK), offset=sharing_bytes.len(), body=None
    let chunk2 = PayloadTransferFrame {
        packet_type: Some(PacketType::Data as i32),
        payload_header: Some(PayloadHeader {
            id: Some(payload_id),
            r#type: Some(PayloadType::Bytes as i32),
            total_size: Some(sharing_bytes.len() as i64),
            is_sensitive: Some(false),
            file_name: None,
            parent_folder: None,
            last_modified_timestamp_millis: None,
        }),
        payload_chunk: Some(PayloadChunk {
            flags: Some(1),
            offset: Some(sharing_bytes.len() as i64),
            body: None,
            index: Some(1),
        }),
        control_message: None,
    };

    let offline_chunk2 = OfflineFrame {
        version: Some(1),
        v1: Some(ConnectionsV1Frame {
            r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
            connection_request: None,
            connection_response: None,
            payload_transfer: Some(chunk2),
            bandwidth_upgrade_negotiation: None,
            keep_alive: None,
            disconnection: None,
            paired_key_encryption: None,
            authentication_message: None,
            authentication_result: None,
        }),
    };
    send_frame(stream, keys, &offline_chunk2, seq).await
}

async fn read_next_sharing_frame(
    stream: &mut TcpStream,
    keys: &SessionKeys,
    seq: &mut i32,
    bytes_buffers: &mut std::collections::HashMap<i64, Vec<u8>>,
) -> Result<SharingFrame> {
    loop {
        let (frame, _) = read_frame(stream, keys).await?;
        let v1 = match frame.v1 {
            Some(v) => v,
            None => continue,
        };

        debug!("read_next_sharing_frame received frame type: {:?}", v1.r#type());

        match v1.r#type() {
            ConnectionsFrameType::KeepAlive => {
                let is_ack = v1.keep_alive.as_ref().and_then(|k| k.ack).unwrap_or(false);
                if !is_ack {
                    let ack = OfflineFrame {
                        version: Some(1),
                        v1: Some(ConnectionsV1Frame {
                            r#type: Some(ConnectionsFrameType::KeepAlive as i32),
                            connection_request: None,
                            connection_response: None,
                            payload_transfer: None,
                            bandwidth_upgrade_negotiation: None,
                            keep_alive: Some(KeepAliveFrame { ack: Some(true) }),
                            disconnection: None,
                            paired_key_encryption: None,
                            authentication_message: None,
                            authentication_result: None,
                        }),
                    };
                    let _ = send_frame(stream, keys, &ack, seq).await;
                    debug!("Replied to KeepAlive with ACK");
                }
            }
            ConnectionsFrameType::BandwidthUpgradeRetry | ConnectionsFrameType::BandwidthUpgradeNegotiation => {
                debug!("Ignoring bandwidth upgrade from receiver");
            }
            ConnectionsFrameType::PayloadTransfer => {
                if let Some(pt) = v1.payload_transfer {
                    let payload_id = pt.payload_header.as_ref().and_then(|h| h.id).unwrap_or(0);
                    if let Some(chunk) = pt.payload_chunk {
                        if let Some(body) = chunk.body {
                            let entry = bytes_buffers.entry(payload_id).or_default();
                            entry.extend_from_slice(&body);
                        }
                        let is_last = (chunk.flags.unwrap_or(0) & 1) != 0;
                        let total_size = pt.payload_header.as_ref().and_then(|h| h.total_size).unwrap_or(0) as usize;
                        if let Some(buf) = bytes_buffers.get(&payload_id) {
                            if is_last || (total_size > 0 && buf.len() >= total_size) {
                                if let Some(complete_body) = bytes_buffers.remove(&payload_id) {
                                    if let Ok(sh) = SharingFrame::decode(&complete_body[..]) {
                                        info!("Successfully decoded SharingFrame: {:?}", sh.v1.as_ref().map(|v| v.r#type()));
                                        return Ok(sh);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ConnectionsFrameType::PairedKeyEncryption => {
                info!("Received ConnectionsPairedKeyEncryption frame");
                return Ok(SharingFrame {
                    version: Some(1),
                    v1: Some(SharingV1Frame {
                        r#type: Some(SharingFrameType::PairedKeyEncryption as i32),
                        introduction: None,
                        connection_response: None,
                        paired_key_encryption: None,
                        paired_key_result: None,
                        certificate_info: None,
                        progress_update: None,
                    }),
                });
            }
            ConnectionsFrameType::Disconnection => {
                return Err(anyhow!("Peer disconnected before transfer started"));
            }
            other => {
                debug!("Ignoring frame type while waiting for SharingFrame: {:?}", other);
            }
        }
    }
}

fn file_type_from_mime(mime: &str) -> i32 {
    if mime.starts_with("image/") {
        1 // IMAGE
    } else if mime.starts_with("video/") {
        2 // VIDEO
    } else if mime.starts_with("audio/") {
        4 // AUDIO
    } else {
        5 // DOCUMENT
    }
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

use qshare_linux::secure_frame::{decrypt_secure_frame, encrypt_secure_frame, ProtocolRole};
use qshare_linux::ukey2::{perform_ukey2_handshake_client, perform_ukey2_handshake_server};
use tokio::io::duplex;

#[tokio::test]
async fn test_end_to_end_ukey2_and_secure_channel() {
    let (mut client_stream, mut server_stream) = duplex(65536);

    let server_task = tokio::spawn(async move {
        perform_ukey2_handshake_server(&mut server_stream)
            .await
            .expect("Server handshake failed")
    });

    let client_task = tokio::spawn(async move {
        perform_ukey2_handshake_client(&mut client_stream)
            .await
            .expect("Client handshake failed")
    });

    let (server_keys, client_keys) = tokio::join!(server_task, client_task);
    let server_keys = server_keys.unwrap();
    let client_keys = client_keys.unwrap();

    // 1. Mutual 4-digit UKEY2 PIN must match exactly
    assert_eq!(server_keys.pin, client_keys.pin);
    assert_eq!(server_keys.pin.len(), 4);
    println!("Mutual Verification PIN matched: [{}]", server_keys.pin);

    // 2. Encryption test: Client -> Server
    let test_frame = qshare_linux::proto::wire::OfflineFrame {
        version: Some(1),
        v1: None,
    };

    let encrypted_by_client = encrypt_secure_frame(
        &client_keys,
        &test_frame,
        0,
        ProtocolRole::Client,
    ).expect("Client encryption failed");

    let (decrypted_by_server, seq) = decrypt_secure_frame(
        &server_keys,
        &encrypted_by_client,
        ProtocolRole::Server,
    ).expect("Server decryption failed");

    assert_eq!(seq, 0);
    assert_eq!(decrypted_by_server.version, Some(1));

    // 3. Encryption test: Server -> Client
    let encrypted_by_server = encrypt_secure_frame(
        &server_keys,
        &test_frame,
        42,
        ProtocolRole::Server,
    ).expect("Server encryption failed");

    let (decrypted_by_client, seq2) = decrypt_secure_frame(
        &client_keys,
        &encrypted_by_server,
        ProtocolRole::Client,
    ).expect("Client decryption failed");

    assert_eq!(seq2, 42);
    assert_eq!(decrypted_by_client.version, Some(1));
}

#[tokio::test]
async fn test_full_protocol_frame_exchange_flow() {
    use qshare_linux::proto::wire::{
        connection_response_frame::ResponseStatus,
        connections_v1_frame::FrameType as ConnectionsFrameType,
        payload_transfer_frame::{
            payload_header::PayloadType, PayloadChunk, PayloadHeader, PacketType,
        },
        sharing_response_frame::Status as SharingResponseStatus,
        sharing_v1_frame::FrameType as SharingFrameType,
        ConnectionRequestFrame, ConnectionResponseFrame, ConnectionsPairedKeyEncryptionFrame,
        ConnectionsV1Frame, FileMetadata, IntroductionFrame, OfflineFrame,
        PayloadTransferFrame, SharingFrame, SharingResponseFrame, SharingV1Frame,
    };
    use prost::Message;

    let (mut client_stream, mut server_stream) = duplex(65536);

    let server_task = tokio::spawn(async move {
        let keys = perform_ukey2_handshake_server(&mut server_stream)
            .await
            .expect("Server handshake failed");

        // 1. Read ConnectionRequest
        let raw = qshare_linux::transport::read_length_prefixed_frame(&mut server_stream).await.unwrap();
        let (req_frame, _) = decrypt_secure_frame(&keys, &raw, ProtocolRole::Server).unwrap();
        let v1 = req_frame.v1.unwrap();
        assert_eq!(v1.r#type(), ConnectionsFrameType::ConnectionRequest);
        let req = v1.connection_request.unwrap();
        assert_eq!(req.endpoint_name.as_deref(), Some(b"Test Sender".as_slice()));

        // Send ConnectionResponse (ACCEPT)
        let resp = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::ConnectionResponse as i32),
                connection_request: None,
                connection_response: Some(ConnectionResponseFrame {
                    status: Some(ResponseStatus::Accept as i32),
                    handshake_data: None,
                    response: Some(ResponseStatus::Accept as i32),
                    multiplex_socket_bitmask: None,
                    nearby_connections_version: Some(1),
                    safe_to_disconnect_version: None,
                    keep_alive_timeout_millis: Some(5000),
                    wifi_direct_device_name: None,
                    os_info: None,
                }),
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let enc = encrypt_secure_frame(&keys, &resp, 0, ProtocolRole::Server).unwrap();
        qshare_linux::transport::write_length_prefixed_frame(&mut server_stream, &enc).await.unwrap();

        // 2. Read PairedKeyEncryption
        let raw = qshare_linux::transport::read_length_prefixed_frame(&mut server_stream).await.unwrap();
        let (enc_frame, _) = decrypt_secure_frame(&keys, &raw, ProtocolRole::Server).unwrap();
        assert_eq!(enc_frame.v1.unwrap().r#type(), ConnectionsFrameType::PairedKeyEncryption);

        // Send PairedKeyEncryption response
        let enc_resp = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PairedKeyEncryption as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: Some(ConnectionsPairedKeyEncryptionFrame {
                    signed_data: Some(vec![1, 2, 3]),
                    secret_id_hash: None,
                    optional_signed_data: None,
                }),
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let enc2 = encrypt_secure_frame(&keys, &enc_resp, 1, ProtocolRole::Server).unwrap();
        qshare_linux::transport::write_length_prefixed_frame(&mut server_stream, &enc2).await.unwrap();

        // 3. Read IntroductionFrame
        let raw = qshare_linux::transport::read_length_prefixed_frame(&mut server_stream).await.unwrap();
        let (intro_frame, _) = decrypt_secure_frame(&keys, &raw, ProtocolRole::Server).unwrap();
        let intro_payload = intro_frame.v1.unwrap().payload_transfer.unwrap();
        let chunk_body = intro_payload.payload_chunk.unwrap().body.unwrap();
        let sharing_frame = SharingFrame::decode(&chunk_body[..]).unwrap();
        let files = sharing_frame.v1.unwrap().introduction.unwrap().file_metadata;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name.as_deref(), Some("document.pdf"));

        // Send SharingResponseFrame: ACCEPT
        let accept_sharing = SharingFrame {
            version: Some(1),
            v1: Some(SharingV1Frame {
                r#type: Some(SharingFrameType::Response as i32),
                introduction: None,
                connection_response: Some(SharingResponseFrame {
                    status: Some(SharingResponseStatus::Accept as i32),
                }),
                paired_key_encryption: None,
                paired_key_result: None,
                certificate_info: None,
                progress_update: None,
            }),
        };
        let mut accept_bytes = Vec::new();
        accept_sharing.encode(&mut accept_bytes).unwrap();

        let accept_payload = PayloadTransferFrame {
            packet_type: Some(PacketType::Data as i32),
            payload_header: Some(PayloadHeader {
                id: Some(999),
                r#type: Some(PayloadType::Bytes as i32),
                total_size: Some(accept_bytes.len() as i64),
                is_sensitive: None,
                file_name: None,
                parent_folder: None,
                last_modified_timestamp_millis: None,
            }),
            payload_chunk: Some(PayloadChunk {
                flags: Some(1),
                offset: Some(0),
                body: Some(accept_bytes),
                index: Some(0),
            }),
            control_message: None,
        };
        let accept_offline = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: Some(accept_payload),
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let enc3 = encrypt_secure_frame(&keys, &accept_offline, 2, ProtocolRole::Server).unwrap();
        qshare_linux::transport::write_length_prefixed_frame(&mut server_stream, &enc3).await.unwrap();

        // 4. Read File Payload Chunk
        let raw = qshare_linux::transport::read_length_prefixed_frame(&mut server_stream).await.unwrap();
        let (file_frame, _) = decrypt_secure_frame(&keys, &raw, ProtocolRole::Server).unwrap();
        let chunk = file_frame.v1.unwrap().payload_transfer.unwrap().payload_chunk.unwrap();
        let received_body = chunk.body.unwrap();
        assert_eq!(&received_body[..], b"Hello Quick Share from client!");
    });

    let client_task = tokio::spawn(async move {
        let keys = perform_ukey2_handshake_client(&mut client_stream)
            .await
            .expect("Client handshake failed");

        let mut seq = 0i32;

        // 1. Send ConnectionRequest
        let conn_req = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::ConnectionRequest as i32),
                connection_request: Some(ConnectionRequestFrame {
                    endpoint_id: Some("CLNT".to_string()),
                    endpoint_name: Some(b"Test Sender".to_vec()),
                    handshake_data: None,
                    nonce: None,
                    mediums: vec![5],
                    endpoint_info: Some(b"Test Sender".to_vec()),
                    keep_alive_interval_millis: None,
                    keep_alive_timeout_millis: Some(5000),
                    device_type: Some(1),
                    device_info: None,
                    connection_mode: None,
                }),
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
        let enc = encrypt_secure_frame(&keys, &conn_req, seq, ProtocolRole::Client).unwrap();
        seq += 1;
        qshare_linux::transport::write_length_prefixed_frame(&mut client_stream, &enc).await.unwrap();

        // Read ConnectionResponse
        let raw = qshare_linux::transport::read_length_prefixed_frame(&mut client_stream).await.unwrap();
        let (resp_frame, _) = decrypt_secure_frame(&keys, &raw, ProtocolRole::Client).unwrap();
        let resp = resp_frame.v1.unwrap().connection_response.unwrap();
        assert_eq!(resp.status, Some(ResponseStatus::Accept as i32));

        // 2. Send PairedKeyEncryption
        let enc_req = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PairedKeyEncryption as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: None,
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: Some(ConnectionsPairedKeyEncryptionFrame {
                    signed_data: Some(vec![1, 2, 3]),
                    secret_id_hash: None,
                    optional_signed_data: None,
                }),
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let enc = encrypt_secure_frame(&keys, &enc_req, seq, ProtocolRole::Client).unwrap();
        seq += 1;
        qshare_linux::transport::write_length_prefixed_frame(&mut client_stream, &enc).await.unwrap();

        // Read PairedKeyEncryption Response
        let raw = qshare_linux::transport::read_length_prefixed_frame(&mut client_stream).await.unwrap();
        let (resp_enc, _) = decrypt_secure_frame(&keys, &raw, ProtocolRole::Client).unwrap();
        assert_eq!(resp_enc.v1.unwrap().r#type(), ConnectionsFrameType::PairedKeyEncryption);

        // 3. Send IntroductionFrame
        let intro = IntroductionFrame {
            file_metadata: vec![FileMetadata {
                name: Some("document.pdf".to_string()),
                r#type: Some(1),
                payload_id: Some(12345),
                size: Some(30),
                mime_type: Some("application/pdf".to_string()),
                id: Some(101),
                parent_folder: None,
                attachment_hash: None,
                is_sensitive_content: None,
            }],
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
        let sharing = SharingFrame {
            version: Some(1),
            v1: Some(SharingV1Frame {
                r#type: Some(SharingFrameType::Introduction as i32),
                introduction: Some(intro),
                connection_response: None,
                paired_key_encryption: None,
                paired_key_result: None,
                certificate_info: None,
                progress_update: None,
            }),
        };
        let mut sharing_bytes = Vec::new();
        sharing.encode(&mut sharing_bytes).unwrap();

        let intro_payload = PayloadTransferFrame {
            packet_type: Some(PacketType::Data as i32),
            payload_header: Some(PayloadHeader {
                id: Some(111),
                r#type: Some(PayloadType::Bytes as i32),
                total_size: Some(sharing_bytes.len() as i64),
                is_sensitive: None,
                file_name: None,
                parent_folder: None,
                last_modified_timestamp_millis: None,
            }),
            payload_chunk: Some(PayloadChunk {
                flags: Some(1),
                offset: Some(0),
                body: Some(sharing_bytes),
                index: Some(0),
            }),
            control_message: None,
        };
        let intro_offline = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: Some(intro_payload),
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let enc = encrypt_secure_frame(&keys, &intro_offline, seq, ProtocolRole::Client).unwrap();
        seq += 1;
        qshare_linux::transport::write_length_prefixed_frame(&mut client_stream, &enc).await.unwrap();

        // Read SharingResponseFrame
        let raw = qshare_linux::transport::read_length_prefixed_frame(&mut client_stream).await.unwrap();
        let (sh_frame, _) = decrypt_secure_frame(&keys, &raw, ProtocolRole::Client).unwrap();
        let sh_bytes = sh_frame.v1.unwrap().payload_transfer.unwrap().payload_chunk.unwrap().body.unwrap();
        let decoded = SharingFrame::decode(&sh_bytes[..]).unwrap();
        assert_eq!(
            decoded.v1.unwrap().connection_response.unwrap().status,
            Some(SharingResponseStatus::Accept as i32)
        );

        // 4. Send File Data Chunk
        let data_payload = PayloadTransferFrame {
            packet_type: Some(PacketType::Data as i32),
            payload_header: Some(PayloadHeader {
                id: Some(12345),
                r#type: Some(PayloadType::File as i32),
                total_size: Some(30),
                is_sensitive: None,
                file_name: Some("document.pdf".to_string()),
                parent_folder: None,
                last_modified_timestamp_millis: None,
            }),
            payload_chunk: Some(PayloadChunk {
                flags: Some(1),
                offset: Some(0),
                body: Some(b"Hello Quick Share from client!".to_vec()),
                index: Some(0),
            }),
            control_message: None,
        };
        let data_offline = OfflineFrame {
            version: Some(1),
            v1: Some(ConnectionsV1Frame {
                r#type: Some(ConnectionsFrameType::PayloadTransfer as i32),
                connection_request: None,
                connection_response: None,
                payload_transfer: Some(data_payload),
                bandwidth_upgrade_negotiation: None,
                keep_alive: None,
                disconnection: None,
                paired_key_encryption: None,
                authentication_message: None,
                authentication_result: None,
            }),
        };
        let enc = encrypt_secure_frame(&keys, &data_offline, seq, ProtocolRole::Client).unwrap();
        qshare_linux::transport::write_length_prefixed_frame(&mut client_stream, &enc).await.unwrap();
    });

    let (s_res, c_res) = tokio::join!(server_task, client_task);
    s_res.unwrap();
    c_res.unwrap();
}

#[test]
fn test_non_utf8_endpoint_name_decoding() {
    use prost::Message;
    use qshare_linux::proto::wire::{
        connections_v1_frame::FrameType as ConnectionsFrameType,
        ConnectionRequestFrame, ConnectionsV1Frame, OfflineFrame,
    };
    use qshare_linux::session::extract_clean_device_name;

    // Simulate Google Quick Share Windows binary endpoint_name payload:
    // [header(1), salt(16 non-utf8 random bytes), name_len(1), name...]
    let mut raw_endpoint_info = vec![0x06u8]; // header
    let non_utf8_salt = vec![
        0xFF, 0xFE, 0x80, 0x81, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x12, 0x34, 0x56, 0x78, 0x9A,
        0xBC, 0xDE,
    ];
    raw_endpoint_info.extend_from_slice(&non_utf8_salt);
    let dev_name = b"Aditya's PC";
    raw_endpoint_info.push(dev_name.len() as u8);
    raw_endpoint_info.extend_from_slice(dev_name);

    let offline_frame = OfflineFrame {
        version: Some(1),
        v1: Some(ConnectionsV1Frame {
            r#type: Some(ConnectionsFrameType::ConnectionRequest as i32),
            connection_request: Some(ConnectionRequestFrame {
                endpoint_id: Some("2I0P".to_string()),
                endpoint_name: Some(raw_endpoint_info.clone()),
                handshake_data: None,
                nonce: Some(12345),
                mediums: vec![5],
                endpoint_info: Some(raw_endpoint_info.clone()),
                keep_alive_interval_millis: Some(5000),
                keep_alive_timeout_millis: Some(30000),
                device_type: Some(3),
                device_info: None,
                connection_mode: None,
            }),
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

    let mut buf = Vec::new();
    offline_frame.encode(&mut buf).expect("Encode failed");

    // Decoding must succeed and NOT throw "invalid string value: data is not UTF-8 encoded"
    let decoded =
        OfflineFrame::decode(&buf[..]).expect("Decode of non-UTF8 endpoint_name must succeed");
    let req = decoded.v1.unwrap().connection_request.unwrap();
    let name = extract_clean_device_name(req.endpoint_name.as_ref().unwrap());
    assert_eq!(name, "Aditya's PC");
}

#[tokio::test]
async fn test_framed_reader_streaming_and_partial_chunks() {
    use qshare_linux::transport::{write_length_prefixed_frame, FramedReader};
    use tokio::io::duplex;

    let (mut client, server) = duplex(1024);
    let mut reader = FramedReader::new(server);

    // Write 3 frames
    let frame1 = b"Hello".to_vec();
    let frame2 = b"QuickShare".to_vec();
    let frame3 = vec![0x42u8; 10000];

    let f1_clone = frame1.clone();
    let f2_clone = frame2.clone();
    let f3_clone = frame3.clone();

    tokio::spawn(async move {
        write_length_prefixed_frame(&mut client, &f1_clone).await.unwrap();
        write_length_prefixed_frame(&mut client, &f2_clone).await.unwrap();
        write_length_prefixed_frame(&mut client, &f3_clone).await.unwrap();
    });

    let r1 = reader.next_frame().await.unwrap();
    assert_eq!(r1, frame1);

    let r2 = reader.next_frame().await.unwrap();
    assert_eq!(r2, frame2);

    let r3 = reader.next_frame().await.unwrap();
    assert_eq!(r3, frame3);
}



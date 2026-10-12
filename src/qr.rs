use anyhow::{anyhow, Result};
use image::ImageEncoder;
use qrcode::QrCode;
use std::io::Cursor;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrConnectionInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub endpoint_id: String,
    pub device_name: String,
}

impl QrConnectionInfo {
    /// Generate quickshare:// URL
    pub fn to_uri(&self) -> String {
        format!(
            "quickshare://{}:{}/{}?name={}",
            self.ip,
            self.port,
            self.endpoint_id,
            url_encode(&self.device_name)
        )
    }

    /// Parse quickshare:// URI or JSON or IP:PORT
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();

        // 1. Check quickshare:// URL
        if let Some(rest) = input.strip_prefix("quickshare://") {
            // format: {host}:{port}/{path}?name={name}
            let (host_port_path, query) = match rest.split_once('?') {
                Some((hpp, q)) => (hpp, Some(q)),
                None => (rest, None),
            };

            let (host_port, path) = match host_port_path.split_once('/') {
                Some((hp, p)) => (hp, p),
                None => (host_port_path, ""),
            };

            let (host, port) = if let Some((h, p_str)) = host_port.split_once(':') {
                let port: u16 = p_str.parse().map_err(|_| anyhow!("Invalid port: {}", p_str))?;
                (h, port)
            } else {
                (host_port, 8765)
            };

            let ip: IpAddr = host.parse().map_err(|_| anyhow!("Invalid IP address: {}", host))?;
            let endpoint_id = if path.is_empty() {
                "QR01".to_string()
            } else {
                path.to_string()
            };

            let mut device_name = "Quick Share Peer".to_string();
            if let Some(q) = query {
                for pair in q.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        if k == "name" {
                            device_name = url_decode(v);
                        }
                    }
                }
            }

            return Ok(Self {
                ip,
                port,
                endpoint_id,
                device_name,
            });
        }

        // 2. Check JSON
        if input.starts_with('{') && input.ends_with('}') {
            let ip_str = extract_json_field(input, "ip")
                .ok_or_else(|| anyhow!("JSON missing 'ip' field"))?;
            let ip: IpAddr = ip_str.parse().map_err(|_| anyhow!("Invalid IP: {}", ip_str))?;
            let port: u16 = extract_json_field(input, "port")
                .and_then(|p| p.parse().ok())
                .unwrap_or(8765);
            let endpoint_id = extract_json_field(input, "id").unwrap_or_else(|| "QR01".to_string());
            let device_name = extract_json_field(input, "name").unwrap_or_else(|| "QR Peer".to_string());
            return Ok(Self {
                ip,
                port,
                endpoint_id,
                device_name,
            });
        }

        // 3. Fallback: IP:PORT or plain IP
        let parts: Vec<&str> = input.split(':').collect();
        if parts.len() == 2 {
            let ip: IpAddr = parts[0].trim().parse().map_err(|_| anyhow!("Invalid IP: {}", parts[0]))?;
            let port: u16 = parts[1].trim().parse().map_err(|_| anyhow!("Invalid Port: {}", parts[1]))?;
            return Ok(Self {
                ip,
                port,
                endpoint_id: "DIR1".to_string(),
                device_name: format!("Direct Peer ({})", ip),
            });
        } else if parts.len() == 1 {
            let ip: IpAddr = parts[0].trim().parse().map_err(|_| anyhow!("Invalid IP: {}", parts[0]))?;
            return Ok(Self {
                ip,
                port: 8765,
                endpoint_id: "DIR1".to_string(),
                device_name: format!("Direct Peer ({})", ip),
            });
        }

        Err(anyhow!("Unrecognized QR format: {}", input))
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let mut bytes = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            let hex_str: String = [h1, h2].iter().collect();
            if let Ok(b) = u8::from_str_radix(&hex_str, 16) {
                bytes.push(b);
            }
        } else if c == '+' {
            bytes.push(b' ');
        } else {
            bytes.push(c as u8);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\"", field);
    if let Some(pos) = json.find(&key) {
        let rest = &json[pos + key.len()..];
        if let Some(colon) = rest.find(':') {
            let after_colon = rest[colon + 1..].trim_start();
            if after_colon.starts_with('"') {
                let s = &after_colon[1..];
                if let Some(end) = s.find('"') {
                    return Some(s[..end].to_string());
                }
            } else {
                let end = after_colon.find(|c: char| c == ',' || c == '}' || c.is_whitespace()).unwrap_or(after_colon.len());
                return Some(after_colon[..end].trim().to_string());
            }
        }
    }
    None
}

/// Generate QR code PNG bytes for direct pairing
pub fn generate_qr_png_bytes(info: &QrConnectionInfo, size: u32) -> Result<Vec<u8>> {
    let uri = info.to_uri();
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;

    let img = code.render::<image::Rgb<u8>>()
        .min_dimensions(size, size)
        .build();

    let mut png_bytes = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
    encoder
        .write_image(
            img.as_raw(),
            img.width(),
            img.height(),
            image::ExtendedColorType::Rgb8,
        )
        .map_err(|e| anyhow!("Failed to encode QR PNG: {}", e))?;

    Ok(png_bytes)
}

/// Convert QR PNG bytes to gdk_pixbuf::Pixbuf
pub fn generate_qr_pixbuf(info: &QrConnectionInfo, size: u32) -> Result<gdk_pixbuf::Pixbuf> {
    let png_bytes = generate_qr_png_bytes(info, size)?;
    let cursor = Cursor::new(png_bytes);
    let pixbuf = gdk_pixbuf::Pixbuf::from_read(cursor)
        .map_err(|e| anyhow!("Failed to load Pixbuf from QR PNG: {:?}", e))?;
    Ok(pixbuf)
}

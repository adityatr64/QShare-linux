use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read a 4-byte big-endian length-prefixed frame from an async stream.
pub async fn read_length_prefixed_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let length = u32::from_be_bytes(len_buf) as usize;

    if length > 64 * 1024 * 1024 {
        return Err(anyhow!("Frame length exceeds maximum safety limit (64MB): {} bytes", length));
    }

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Write a 4-byte big-endian length-prefixed frame to an async stream.
pub async fn write_length_prefixed_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    let length = payload.len() as u32;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// A buffered, cancellation-safe reader for length-prefixed frames.
pub struct FramedReader<R> {
    reader: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::with_capacity(65536),
        }
    }

    pub async fn next_frame(&mut self) -> Result<Vec<u8>> {
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
                if len > 64 * 1024 * 1024 {
                    return Err(anyhow!("Frame length exceeds maximum safety limit (64MB): {} bytes", len));
                }
                if self.buf.len() >= 4 + len {
                    let frame = self.buf[4..4 + len].to_vec();
                    self.buf.drain(..4 + len);
                    return Ok(frame);
                }
            }
            let mut chunk = [0u8; 65536];
            let n = self.reader.read(&mut chunk).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "early eof").into());
                } else {
                    return Err(anyhow!("Unexpected EOF with partial frame ({} bytes remaining)", self.buf.len()));
                }
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

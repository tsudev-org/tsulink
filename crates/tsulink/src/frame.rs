//! Khung tin trên luồng mTLS: 4 byte độ dài (big-endian) + nội dung.
//!
//! - [`write`]/[`read`]: khung điều khiển JSON, tối đa [`MAX_FRAME`] byte;
//! - [`write_bytes`]/[`read_bytes`] và [`write_json_max`]/[`read_json_max`]: khung lớn hơn (khối tệp, tin Automerge,
//!   lô bản ghi) với giới hạn do bên gọi đặt, không vượt [`MAX_BLOB`].

use crate::Error;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Kích thước tối đa một khung điều khiển (64 KiB).
pub const MAX_FRAME: usize = 64 * 1024;

/// Giới hạn cứng của mọi khung lớn (32 MiB) - chặn thiết bị đã ghép đôi làm cạn bộ nhớ.
pub const MAX_BLOB: usize = 32 * 1024 * 1024;

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e.kind())
}

/// Gửi một khung JSON.
pub async fn write<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<(), Error> {
    write_json_max(w, msg, MAX_FRAME).await
}

/// Đọc một khung JSON.
pub async fn read<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T, Error> {
    read_json_max(r, MAX_FRAME).await
}

/// Gửi một khung JSON dài tối đa `max` byte.
pub async fn write_json_max<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
    max: usize,
) -> Result<(), Error> {
    let body = serde_json::to_vec(msg).map_err(|_| Error::Protocol("khung"))?;
    write_bytes(w, &body, max).await
}

/// Đọc một khung JSON dài tối đa `max` byte.
pub async fn read_json_max<R: AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
    max: usize,
) -> Result<T, Error> {
    let body = read_bytes(r, max).await?;
    serde_json::from_slice(&body).map_err(|_| Error::Protocol("khung hỏng"))
}

/// Gửi một khung nhị phân dài tối đa `max` byte (và không quá [`MAX_BLOB`]).
pub async fn write_bytes<W: AsyncWrite + Unpin>(
    w: &mut W,
    body: &[u8],
    max: usize,
) -> Result<(), Error> {
    if body.len() > max.min(MAX_BLOB) {
        return Err(Error::Protocol("khung quá lớn"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(io_err)?;
    w.write_all(body).await.map_err(io_err)?;
    w.flush().await.map_err(io_err)
}

/// Đọc một khung nhị phân dài tối đa `max` byte (và không quá [`MAX_BLOB`]).
pub async fn read_bytes<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>, Error> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.map_err(io_err)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max.min(MAX_BLOB) {
        return Err(Error::Protocol("khung quá lớn"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(io_err)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn khu_hoi_va_tu_choi_khung_qua_lon() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        write(&mut a, &serde_json::json!({"x": 1})).await.unwrap();
        let v: serde_json::Value = read(&mut b).await.unwrap();
        assert_eq!(v["x"], 1);
        a.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        let r: Result<serde_json::Value, _> = read(&mut b).await;
        assert_eq!(r.unwrap_err(), Error::Protocol("khung quá lớn"));
    }
}

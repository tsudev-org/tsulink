//! Khung tin trên luồng mTLS: 4 byte độ dài (big-endian) + JSON. Tối đa [`MAX_FRAME`] byte mỗi khung.

use crate::Error;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Kích thước tối đa một khung điều khiển (64 KiB).
pub const MAX_FRAME: usize = 64 * 1024;

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e.kind())
}

/// Gửi một khung JSON.
pub async fn write<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<(), Error> {
    let body = serde_json::to_vec(msg).map_err(|_| Error::Protocol("khung"))?;
    if body.len() > MAX_FRAME {
        return Err(Error::Protocol("khung quá lớn"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(io_err)?;
    w.write_all(&body).await.map_err(io_err)?;
    w.flush().await.map_err(io_err)
}

/// Đọc một khung JSON.
pub async fn read<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T, Error> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.map_err(io_err)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(Error::Protocol("khung quá lớn"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(io_err)?;
    serde_json::from_slice(&body).map_err(|_| Error::Protocol("khung hỏng"))
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

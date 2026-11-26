//! Truyền tệp theo khối (`LOCAL_SYNC.md` mục 4): khối [`CHUNK_SIZE`] = 1 MiB, mỗi khối kiểm BLAKE3; tệp định danh bằng
//! BLAKE3 của toàn bộ nội dung.
//!
//! Bên nhận ghi vào `<đích>.tsulink-part`. Đứt giữa chừng ⇒ lần sau đọc lại phần đã có, kiểm từng khối với bảng khối
//! ([`Manifest`]) và xin tiếp từ khối đầu tiên còn thiếu/hỏng - không nhận lại khối đã có, không nhân đôi. Đủ khối và
//! khớp BLAKE3 toàn tệp mới `fsync` rồi đổi tên nguyên tử thành tệp đích (thay bản cũ).

use crate::Error;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Kích thước khối (1 MiB).
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// Đuôi tệp đang nhận dở.
pub const PART_SUFFIX: &str = ".tsulink-part";

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e.kind())
}

/// BLAKE3 hex chữ thường (64 ký tự).
pub fn hash_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Kiểm chuỗi là BLAKE3 hex chữ thường.
pub fn is_valid_hash(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Bảng khối của một tệp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// BLAKE3 toàn tệp (định danh tệp).
    pub hash: String,
    /// Kích thước (byte).
    pub size: u64,
    /// BLAKE3 từng khối, theo thứ tự.
    pub chunks: Vec<String>,
}

impl Manifest {
    /// Đọc tệp và lập bảng khối.
    pub async fn of_file(path: &Path) -> Result<Self, Error> {
        let mut f = tokio::fs::File::open(path).await.map_err(io_err)?;
        let mut whole = blake3::Hasher::new();
        let mut chunks = Vec::new();
        let mut size = 0u64;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = read_full(&mut f, &mut buf).await?;
            if n == 0 {
                break;
            }
            whole.update(&buf[..n]);
            chunks.push(hash_hex(&buf[..n]));
            size += n as u64;
            if n < CHUNK_SIZE {
                break;
            }
        }
        Ok(Self {
            hash: whole.finalize().to_hex().to_string(),
            size,
            chunks,
        })
    }

    /// Bảng khối nhất quán: số khối khớp kích thước, mọi băm đúng khuôn.
    pub fn is_consistent(&self) -> bool {
        let expect = self.size.div_ceil(CHUNK_SIZE as u64);
        is_valid_hash(&self.hash)
            && self.chunks.len() as u64 == expect
            && self.chunks.iter().all(|c| is_valid_hash(c))
    }

    /// Độ dài khối thứ `i`.
    pub fn chunk_len(&self, i: usize) -> usize {
        let start = i as u64 * CHUNK_SIZE as u64;
        (self.size - start).min(CHUNK_SIZE as u64) as usize
    }
}

/// Đọc tới khi đầy `buf` hoặc hết tệp; trả số byte đã đọc.
async fn read_full(f: &mut tokio::fs::File, buf: &mut [u8]) -> Result<usize, Error> {
    let mut n = 0;
    while n < buf.len() {
        let k = f.read(&mut buf[n..]).await.map_err(io_err)?;
        if k == 0 {
            break;
        }
        n += k;
    }
    Ok(n)
}

/// Đọc khối thứ `i` của tệp nguồn.
pub async fn read_chunk(path: &Path, m: &Manifest, i: usize) -> Result<Vec<u8>, Error> {
    use tokio::io::AsyncSeekExt;
    let mut f = tokio::fs::File::open(path).await.map_err(io_err)?;
    f.seek(std::io::SeekFrom::Start(i as u64 * CHUNK_SIZE as u64))
        .await
        .map_err(io_err)?;
    let mut buf = vec![0u8; m.chunk_len(i)];
    if read_full(&mut f, &mut buf).await? != buf.len() {
        return Err(Error::Corrupt("tệp nguồn đổi trong lúc gửi"));
    }
    Ok(buf)
}

/// Tệp đang nhận.
#[derive(Debug)]
pub struct Receiver {
    dest: PathBuf,
    part: PathBuf,
    manifest: Manifest,
    file: tokio::fs::File,
    next: usize,
}

impl Receiver {
    /// Mở (hoặc nối lại) tệp nhận cho `dest`. Khối đã có trong tệp dở mà khớp bảng khối được giữ; từ khối hỏng đầu tiên
    /// trở đi bị cắt bỏ.
    pub async fn open(dest: &Path, manifest: Manifest) -> Result<Self, Error> {
        if !manifest.is_consistent() {
            return Err(Error::Protocol("bảng khối sai"));
        }
        let mut name = dest
            .file_name()
            .ok_or(Error::Protocol("đường dẫn đích"))?
            .to_os_string();
        name.push(PART_SUFFIX);
        let part = dest.with_file_name(name);
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&part)
            .await
            .map_err(io_err)?;
        let mut next = 0;
        let mut buf = vec![0u8; CHUNK_SIZE];
        while next < manifest.chunks.len() {
            let want = manifest.chunk_len(next);
            let n = read_full(&mut file, &mut buf[..want]).await?;
            if n != want || hash_hex(&buf[..n]) != manifest.chunks[next] {
                break;
            }
            next += 1;
        }
        let keep = next as u64 * CHUNK_SIZE as u64;
        file.set_len(keep.min(manifest.size))
            .await
            .map_err(io_err)?;
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(keep.min(manifest.size)))
            .await
            .map_err(io_err)?;
        Ok(Self {
            dest: dest.to_owned(),
            part,
            manifest,
            file,
            next,
        })
    }

    /// Khối kế tiếp cần nhận (= số khối đã có).
    pub fn next_chunk(&self) -> usize {
        self.next
    }

    /// Đã đủ khối chưa.
    pub fn is_complete(&self) -> bool {
        self.next == self.manifest.chunks.len()
    }

    /// Số byte đã có.
    pub fn received(&self) -> u64 {
        (self.next as u64 * CHUNK_SIZE as u64).min(self.manifest.size)
    }

    /// Bảng khối.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Ghi khối kế tiếp; `Err(Corrupt)` nếu sai độ dài hoặc BLAKE3 (khối bị bỏ, tệp dở giữ nguyên).
    pub async fn push(&mut self, chunk: &[u8]) -> Result<(), Error> {
        if self.is_complete() {
            return Err(Error::Protocol("thừa khối"));
        }
        if chunk.len() != self.manifest.chunk_len(self.next)
            || hash_hex(chunk) != self.manifest.chunks[self.next]
        {
            return Err(Error::Corrupt("khối sai BLAKE3"));
        }
        self.file.write_all(chunk).await.map_err(io_err)?;
        // `tokio::fs::File` ghi ở luồng nền: chưa `flush` mà phiên đứt (bỏ `Receiver`) thì khối vừa nhận có thể chưa
        // xuống tệp dở ⇒ nối lại phải tải lại (test `tep_khoi_blake3_dut_giua_chung...` chập chờn khi máy bận).
        self.file.flush().await.map_err(io_err)?;
        self.next += 1;
        Ok(())
    }

    /// Đủ khối ⇒ kiểm BLAKE3 toàn tệp, `fsync`, đổi tên nguyên tử thành tệp đích. Sai ⇒ xoá tệp dở, `Err(Corrupt)`.
    pub async fn finish(mut self) -> Result<PathBuf, Error> {
        if !self.is_complete() {
            return Err(Error::Protocol("chưa đủ khối"));
        }
        self.file.flush().await.map_err(io_err)?;
        self.file.sync_all().await.map_err(io_err)?;
        drop(self.file);
        let got = Manifest::of_file(&self.part).await?;
        if got.hash != self.manifest.hash || got.size != self.manifest.size {
            let _ = tokio::fs::remove_file(&self.part).await;
            return Err(Error::Corrupt("tệp nhận không khớp BLAKE3"));
        }
        tokio::fs::rename(&self.part, &self.dest)
            .await
            .map_err(io_err)?;
        Ok(self.dest)
    }
}

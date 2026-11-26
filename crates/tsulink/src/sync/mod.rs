//! Khung đồng bộ (`LOCAL_SYNC.md` mục 4, ADR-0004) chạy trên một kết nối mTLS `tsulink/1` đã ghép đôi
//! ([`crate::transport`]) - hoặc bất kỳ luồng hai chiều nào (test dùng `tokio::io::duplex`).
//!
//! Thứ tự một phiên ([`run`]), bên gọi = [`Role::Initiator`], bên nghe = [`Role::Responder`]:
//!
//! 1. **Bắt tay** ([`handshake`]): hai bên gửi `{"t":"hello","proto":1,"app","schema"}`. Khác `app` ⇒ lỗi giao thức;
//!    khác `schema_version` ⇒ [`Error::SchemaMismatch`] - app dừng và nhắc cập nhật (luật L5).
//! 2. **Bảng** ([`pull_rows`]/[`serve_rows`]): bên gọi kéo trước, rồi bên nghe kéo. Bên kéo gửi [`Cursor`] đã lưu, bên
//!    kia gửi các lô phiên bản có `seq` lớn hơn; mỗi lô gộp xong mới lưu con trỏ ⇒ đứt giữa chừng thì lần sau nối tiếp,
//!    gộp lại lô dở cũng không nhân đôi (LWW idempotent).
//! 3. **Tài liệu** ([`sync_docs`]): giao thức đồng bộ của Automerge (bloom filter + thay đổi còn thiếu), lần lượt từng
//!    tài liệu, hai bên luân phiên tới khi cả hai không còn gì để gửi.
//! 4. **Tệp** ([`fetch_file`]/[`serve_files`]): bên gọi xin các tệp còn thiếu, rồi bên nghe xin; khối 1 MiB BLAKE3,
//!    nối lại khi đứt ([`file`]).
//!
//! Mọi hàm là `async` - huỷ được bằng cách bỏ future (dữ liệu cục bộ không hỏng: bản ghi gộp từng cái, tệp chỉ thay
//! khi đủ và khớp). App chạy trên luồng nền và hiện tiến độ qua [`Progress`].

pub mod file;
pub mod hlc;
pub mod table;

pub use automerge;

use crate::{Error, frame};
use automerge::AutoCommit;
use automerge::sync::{Message as AmMessage, State as AmState, SyncDoc};
use file::{Manifest, Receiver};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use table::{Cursor, Replica, Row, RowStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

/// Phiên bản giao thức khung đồng bộ.
pub const PROTO: u32 = 1;
/// Một lô bản ghi tối đa bấy nhiêu byte JSON (1 MiB); một bản ghi đơn lớn hơn ⇒ app nên chuyển phần lớn thành tệp.
pub const MAX_ROWS_FRAME: usize = 1024 * 1024;
/// Tối đa số bản ghi một lô.
pub const ROWS_PER_BATCH: usize = 512;
/// Tin Automerge tối đa (= [`frame::MAX_BLOB`]).
pub const MAX_DOC_MSG: usize = frame::MAX_BLOB;
/// Số vòng luân phiên tối đa cho một tài liệu (thực tế 2-4 vòng).
pub const MAX_DOC_ROUNDS: usize = 64;
/// Thời hạn chờ một tin của bên kia.
pub const MSG_TIMEOUT: Duration = Duration::from_secs(60);

/// Vai trong phiên.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Bên mở kết nối.
    Initiator,
    /// Bên nhận kết nối.
    Responder,
}

/// Cấu hình bắt tay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConfig {
    /// Mã app (như trong QR), hai bên phải trùng.
    pub app: String,
    /// Phiên bản lược đồ dữ liệu của app, hai bên phải trùng.
    pub schema_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Msg {
    Hello {
        proto: u32,
        app: String,
        schema: u32,
    },
    Pull {
        #[serde(default)]
        log: Option<String>,
        after: u64,
    },
    Rows {
        log: String,
        rows: Vec<(u64, Row)>,
        more: bool,
    },
    Docs {
        ids: Vec<String>,
    },
    FileStat {
        hash: String,
    },
    Manifest {
        m: Manifest,
    },
    NoFile,
    FileGet {
        hash: String,
        from: usize,
    },
    Done,
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, m: &Msg) -> Result<(), Error> {
    frame::write_json_max(s, m, frame::MAX_BLOB).await
}

async fn recv<S: AsyncRead + Unpin>(s: &mut S) -> Result<Msg, Error> {
    // Bảng khối của tệp lớn có thể dài (64 byte/MiB) ⇒ cho phép tới MAX_BLOB.
    timeout(MSG_TIMEOUT, frame::read_json_max(s, frame::MAX_BLOB))
        .await
        .map_err(|_| Error::Timeout)?
}

async fn recv_bytes<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> Result<Vec<u8>, Error> {
    timeout(MSG_TIMEOUT, frame::read_bytes(s, max))
        .await
        .map_err(|_| Error::Timeout)?
}

/// Bắt tay: trao `proto`, `app`, `schema_version`. Khác lược đồ ⇒ [`Error::SchemaMismatch`].
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    cfg: &SyncConfig,
) -> Result<(), Error> {
    send(
        s,
        &Msg::Hello {
            proto: PROTO,
            app: cfg.app.clone(),
            schema: cfg.schema_version,
        },
    )
    .await?;
    match recv(s).await? {
        Msg::Hello { proto, app, schema } => {
            if proto != PROTO {
                Err(Error::Protocol("khác phiên bản giao thức đồng bộ"))
            } else if app != cfg.app {
                Err(Error::Protocol("khác app"))
            } else if schema != cfg.schema_version {
                Err(Error::SchemaMismatch {
                    local: cfg.schema_version,
                    remote: schema,
                })
            } else {
                Ok(())
            }
        }
        _ => Err(Error::Protocol("thiếu hello")),
    }
}

/// Kéo các phiên bản bản ghi mới của thiết bị `peer` (vân tay) về `replica`. Trả số phiên bản đã thắng và được ghi.
pub async fn pull_rows<S: AsyncRead + AsyncWrite + Unpin, R: RowStore>(
    s: &mut S,
    replica: &Replica<R>,
    peer: &str,
    now_ms: u64,
) -> Result<usize, Error> {
    let cur = replica.store().cursor(peer);
    send(
        s,
        &Msg::Pull {
            log: cur.as_ref().map(|c| c.log.clone()),
            after: cur.as_ref().map_or(0, |c| c.seq),
        },
    )
    .await?;
    let mut applied = 0;
    loop {
        let Msg::Rows { log, rows, more } = recv(s).await? else {
            return Err(Error::Protocol("chờ rows"));
        };
        let mut last = None;
        for (seq, row) in rows {
            if replica.merge(row, now_ms)? {
                applied += 1;
            }
            last = Some(seq);
        }
        if let Some(seq) = last {
            replica.store().set_cursor(peer, Cursor { log, seq });
        }
        if !more {
            return Ok(applied);
        }
    }
}

/// Trả lời một yêu cầu [`pull_rows`] của bên kia bằng nhật ký của `replica`.
pub async fn serve_rows<S: AsyncRead + AsyncWrite + Unpin, R: RowStore>(
    s: &mut S,
    replica: &Replica<R>,
) -> Result<(), Error> {
    let Msg::Pull { log, after } = recv(s).await? else {
        return Err(Error::Protocol("chờ pull"));
    };
    let my_log = replica.store().log_id();
    // Mã nhật ký khác (kho làm lại) ⇒ gửi lại từ đầu.
    let mut after = if log.as_deref() == Some(my_log.as_str()) {
        after
    } else {
        0
    };
    loop {
        let mut batch = replica.store().changes_after(after, ROWS_PER_BATCH);
        let full = batch.len() == ROWS_PER_BATCH;
        // Cắt lô cho vừa khung.
        let mut size = 0;
        let mut keep = 0;
        for (_, r) in &batch {
            let n = serde_json::to_vec(r)
                .map_err(|_| Error::Protocol("bản ghi"))?
                .len()
                + 32;
            if n > MAX_ROWS_FRAME {
                return Err(Error::Protocol("bản ghi quá lớn"));
            }
            if size + n > MAX_ROWS_FRAME {
                break;
            }
            size += n;
            keep += 1;
        }
        let more = full || keep < batch.len();
        batch.truncate(keep);
        if let Some((seq, _)) = batch.last() {
            after = *seq;
        }
        send(
            s,
            &Msg::Rows {
                log: my_log.clone(),
                rows: batch,
                more,
            },
        )
        .await?;
        if !more {
            return Ok(());
        }
    }
}

/// Đồng bộ các tài liệu Automerge theo mã tài liệu. Tài liệu chỉ một bên có sẽ được tạo ở bên kia. Trả số tài liệu có
/// thay đổi nhận về.
pub async fn sync_docs<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    role: Role,
    docs: &mut BTreeMap<String, AutoCommit>,
) -> Result<usize, Error> {
    let mine: Vec<String> = docs.keys().cloned().collect();
    let theirs = match role {
        Role::Initiator => {
            send(s, &Msg::Docs { ids: mine.clone() }).await?;
            docs_reply(s).await?
        }
        Role::Responder => {
            let t = docs_reply(s).await?;
            send(s, &Msg::Docs { ids: mine.clone() }).await?;
            t
        }
    };
    let all: BTreeSet<String> = mine.into_iter().chain(theirs).collect();
    let mut changed = 0;
    for id in all {
        let doc = docs.entry(id).or_default();
        let before = doc.get_heads();
        let mut state = AmState::new();
        for round in 0.. {
            if round == MAX_DOC_ROUNDS {
                return Err(Error::Protocol("đồng bộ tài liệu không hội tụ"));
            }
            let (sent, got) = match role {
                Role::Initiator => {
                    let sent = send_doc_msg(s, doc, &mut state).await?;
                    (sent, recv_doc_msg(s, doc, &mut state).await?)
                }
                Role::Responder => {
                    let got = recv_doc_msg(s, doc, &mut state).await?;
                    (send_doc_msg(s, doc, &mut state).await?, got)
                }
            };
            if !sent && !got {
                break;
            }
        }
        if doc.get_heads() != before {
            changed += 1;
        }
    }
    Ok(changed)
}

async fn docs_reply<S: AsyncRead + Unpin>(s: &mut S) -> Result<Vec<String>, Error> {
    match recv(s).await? {
        Msg::Docs { ids } => Ok(ids),
        _ => Err(Error::Protocol("chờ docs")),
    }
}

/// Gửi tin Automerge kế tiếp (khung rỗng = không có gì); trả `true` nếu có tin.
async fn send_doc_msg<S: AsyncWrite + Unpin>(
    s: &mut S,
    doc: &mut AutoCommit,
    state: &mut AmState,
) -> Result<bool, Error> {
    let msg = doc.sync().generate_sync_message(state);
    let bytes = msg.map(AmMessage::encode).unwrap_or_default();
    frame::write_bytes(s, &bytes, MAX_DOC_MSG).await?;
    Ok(!bytes.is_empty())
}

async fn recv_doc_msg<S: AsyncRead + Unpin>(
    s: &mut S,
    doc: &mut AutoCommit,
    state: &mut AmState,
) -> Result<bool, Error> {
    let bytes = recv_bytes(s, MAX_DOC_MSG).await?;
    if bytes.is_empty() {
        return Ok(false);
    }
    let msg = AmMessage::decode(&bytes).map_err(|_| Error::Protocol("tin Automerge hỏng"))?;
    doc.sync()
        .receive_sync_message(state, msg)
        .map_err(|_| Error::Protocol("tin Automerge không áp được"))?;
    Ok(true)
}

/// App chỉ ra tệp theo BLAKE3 để phục vụ máy kia.
pub trait FileProvider: Send + Sync {
    /// Đường dẫn tệp có BLAKE3 = `hash`, nếu máy này có.
    fn path_of(&self, hash: &str) -> Option<PathBuf>;
}

impl<F: Fn(&str) -> Option<PathBuf> + Send + Sync> FileProvider for F {
    fn path_of(&self, hash: &str) -> Option<PathBuf> {
        self(hash)
    }
}

/// Nhận tiến độ truyền tệp: `(BLAKE3 tệp, byte đã có, tổng byte)`.
pub type Progress<'a> = &'a mut (dyn FnMut(&str, u64, u64) + Send);

/// Xin tệp có BLAKE3 `hash` và lưu thành `dest` (nối lại phần đã nhận dở). `Ok(None)` nếu máy kia không có tệp.
pub async fn fetch_file<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    hash: &str,
    dest: &Path,
    progress: Progress<'_>,
) -> Result<Option<PathBuf>, Error> {
    if !file::is_valid_hash(hash) {
        return Err(Error::Protocol("BLAKE3 sai khuôn"));
    }
    send(s, &Msg::FileStat { hash: hash.into() }).await?;
    let m = match recv(s).await? {
        Msg::Manifest { m } if m.hash == hash => m,
        Msg::NoFile => return Ok(None),
        _ => return Err(Error::Protocol("chờ manifest")),
    };
    let mut rx = Receiver::open(dest, m).await?;
    progress(hash, rx.received(), rx.manifest().size);
    if !rx.is_complete() {
        send(
            s,
            &Msg::FileGet {
                hash: hash.into(),
                from: rx.next_chunk(),
            },
        )
        .await?;
        while !rx.is_complete() {
            let chunk = recv_bytes(s, file::CHUNK_SIZE).await?;
            rx.push(&chunk).await?;
            progress(hash, rx.received(), rx.manifest().size);
        }
    }
    rx.finish().await.map(Some)
}

/// Phục vụ các yêu cầu [`fetch_file`] cho tới khi bên kia gửi [`finish_files`]. Chỉ phục vụ tệp `provider` chỉ ra.
pub async fn serve_files<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    provider: &dyn FileProvider,
) -> Result<(), Error> {
    let mut open: Option<(PathBuf, Manifest)> = None;
    loop {
        match recv(s).await? {
            Msg::Done => return Ok(()),
            Msg::FileStat { hash } => match provider.path_of(&hash) {
                Some(p) => {
                    let m = Manifest::of_file(&p).await?;
                    if m.hash != hash {
                        // Tệp đã đổi nội dung - coi như không có.
                        send(s, &Msg::NoFile).await?;
                        continue;
                    }
                    send(s, &Msg::Manifest { m: m.clone() }).await?;
                    open = Some((p, m));
                }
                None => send(s, &Msg::NoFile).await?,
            },
            Msg::FileGet { hash, from } => {
                let Some((p, m)) = open.as_ref().filter(|(_, m)| m.hash == hash) else {
                    return Err(Error::Protocol("file_get chưa có file_stat"));
                };
                if from > m.chunks.len() {
                    return Err(Error::Protocol("khối ngoài phạm vi"));
                }
                for i in from..m.chunks.len() {
                    let chunk = file::read_chunk(p, m, i).await?;
                    if file::hash_hex(&chunk) != m.chunks[i] {
                        return Err(Error::Corrupt("tệp nguồn đổi trong lúc gửi"));
                    }
                    frame::write_bytes(s, &chunk, file::CHUNK_SIZE).await?;
                }
            }
            _ => return Err(Error::Protocol("tin tệp không hợp lệ")),
        }
    }
}

/// Báo bên kia ([`serve_files`]) là đã xin xong tệp.
pub async fn finish_files<S: AsyncWrite + Unpin>(s: &mut S) -> Result<(), Error> {
    send(s, &Msg::Done).await
}

/// Dữ liệu của một bên cho [`run`].
pub struct SyncData<'a, R: RowStore> {
    /// Bản sao bảng.
    pub replica: &'a Replica<R>,
    /// Tài liệu Automerge theo mã.
    pub docs: &'a mut BTreeMap<String, AutoCommit>,
    /// Phục vụ tệp cho máy kia.
    pub files: &'a dyn FileProvider,
    /// Tệp máy này còn thiếu: `(BLAKE3, đường dẫn lưu)`. App thường lấy từ bản ghi vừa gộp ⇒ có thể gọi [`run`] hai
    /// lần, hoặc dùng [`fetch_file`] riêng.
    pub wanted: Vec<(String, PathBuf)>,
}

/// Kết quả một phiên.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Số phiên bản bản ghi nhận về và đã thắng.
    pub rows: usize,
    /// Số tài liệu có thay đổi nhận về.
    pub docs: usize,
    /// Tệp đã nhận đủ.
    pub files: Vec<PathBuf>,
    /// BLAKE3 các tệp máy kia không có.
    pub missing: Vec<String>,
}

/// Chạy trọn một phiên đồng bộ với thiết bị `peer` (vân tay - lấy từ [`crate::transport::PeerConnection`]).
pub async fn run<S: AsyncRead + AsyncWrite + Unpin, R: RowStore>(
    s: &mut S,
    role: Role,
    cfg: &SyncConfig,
    peer: &str,
    data: SyncData<'_, R>,
    now_ms: u64,
    progress: Progress<'_>,
) -> Result<SyncReport, Error> {
    handshake(s, cfg).await?;
    let mut rep = SyncReport::default();
    match role {
        Role::Initiator => {
            rep.rows = pull_rows(s, data.replica, peer, now_ms).await?;
            serve_rows(s, data.replica).await?;
        }
        Role::Responder => {
            serve_rows(s, data.replica).await?;
            rep.rows = pull_rows(s, data.replica, peer, now_ms).await?;
        }
    }
    rep.docs = sync_docs(s, role, data.docs).await?;
    let fetch = async |s: &mut S, rep: &mut SyncReport, progress: Progress<'_>| {
        for (hash, dest) in &data.wanted {
            match fetch_file(s, hash, dest, &mut *progress).await? {
                Some(p) => rep.files.push(p),
                None => rep.missing.push(hash.clone()),
            }
        }
        finish_files(s).await
    };
    match role {
        Role::Initiator => {
            fetch(s, &mut rep, &mut *progress).await?;
            serve_files(s, data.files).await?;
        }
        Role::Responder => {
            serve_files(s, data.files).await?;
            fetch(s, &mut rep, &mut *progress).await?;
        }
    }
    Ok(rep)
}

#[cfg(test)]
mod tests;

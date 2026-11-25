//! Kiểm thử `.tsubak` - `LOCAL_SYNC.md` mục 10: xuất rồi nhập lại khớp từng byte; sai mật khẩu ⇒ lỗi rõ, không hỏng.

use super::*;

const APP: &str = "qulythuchi";
const PW: &str = "Mật khẩu sao lưu 2026";
const NOW: u64 = 1_795_000_000;

fn entries() -> Vec<Entry> {
    vec![
        Entry {
            path: "data/thu-chi.csv".into(),
            data: "ngay,so_tien,ghi_chu\n26/11/2026,-45000,Cà phê\n"
                .as_bytes()
                .to_vec(),
        },
        Entry {
            path: "data/cai-dat.json".into(),
            data: br#"{"tien_te":"VND"}"#.to_vec(),
        },
        Entry {
            path: "files/hoa-don/1.bin".into(),
            data: (0..200_000u32).map(|i| (i * 31 + 7) as u8).collect(),
        },
        Entry {
            path: "rong.txt".into(),
            data: Vec::new(),
        },
    ]
}

/// Chi phí KDF thấp nhất cho phép (2 lượt / 19 MiB) để test nhanh; mặc định thật là 3 lượt / 64 MiB.
fn export_fast(pw: Option<&str>) -> Vec<u8> {
    export_with_cost(APP, 3, &entries(), pw, NOW, crypto::KDF_MIN).unwrap()
}

#[test]
fn khong_ma_hoa_khu_hoi_tung_byte_va_mo_bang_trinh_giai_nen_thuong() {
    let bytes = export(APP, 3, &entries(), None, NOW).unwrap();
    assert_eq!(
        inspect(&bytes).unwrap(),
        Info {
            app: APP.into(),
            encrypted: false
        }
    );
    let b = import(&bytes, APP, None).unwrap();
    assert_eq!(b.entries, entries());
    assert_eq!(b.manifest.schema_version, 3);
    assert_eq!(b.manifest.created_at, NOW);
    // Định dạng mở: zip thường đọc được bản kê + tệp CSV.
    let mut z = ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let mut csv = String::new();
    z.by_name("data/thu-chi.csv")
        .unwrap()
        .read_to_string(&mut csv)
        .unwrap();
    assert!(csv.contains("Cà phê"));
    assert!(z.by_name(MANIFEST).is_ok());
}

#[test]
fn co_ma_hoa_khu_hoi_tung_byte_va_khong_lo_ten_tep() {
    let bytes = export_fast(Some(PW));
    assert!(inspect(&bytes).unwrap().encrypted);
    let z = ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let names: Vec<_> = z.file_names().map(|n| n.unwrap().into_owned()).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(!String::from_utf8_lossy(&bytes).contains("thu-chi"));
    let b = import(&bytes, APP, Some(PW)).unwrap();
    assert_eq!(b.entries, entries());
    // Mật khẩu gõ dạng NFD (macOS/iOS) vẫn mở được.
    use unicode_normalization::UnicodeNormalization;
    let nfd: String = PW.nfd().collect();
    assert_ne!(nfd, PW);
    assert_eq!(import(&bytes, APP, Some(&nfd)).unwrap().entries, entries());
}

#[test]
fn mac_dinh_dung_argon2id_64mib_3_luot() {
    let bytes = export(APP, 1, &entries()[..1], Some(PW), NOW).unwrap();
    let mut z = ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let mut m = String::new();
    z.by_name(MANIFEST).unwrap().read_to_string(&mut m).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m).unwrap();
    assert_eq!(v["kdf"]["alg"], "argon2id13");
    assert_eq!(v["kdf"]["ops"], 3);
    assert_eq!(v["kdf"]["mem"], 64 * 1024 * 1024);
}

#[test]
fn sai_hoac_thieu_mat_khau_bao_loi_ro() {
    let bytes = export_fast(Some(PW));
    assert_eq!(
        import(&bytes, APP, Some("mật khẩu sai hoàn toàn")).unwrap_err(),
        Error::WrongPassword
    );
    assert_eq!(import(&bytes, APP, None).unwrap_err(), Error::WrongPassword);
    // Tệp không bị đổi sau lần mở sai.
    assert_eq!(import(&bytes, APP, Some(PW)).unwrap().entries, entries());
}

#[test]
fn mat_khau_yeu_bi_tu_choi() {
    assert_eq!(
        export(APP, 1, &entries(), Some("ngan"), NOW).unwrap_err(),
        Error::WeakPassword
    );
}

/// Sửa một byte trong một tệp của zip (giữ khuôn zip hợp lệ bằng cách ghi lại).
fn rewrite(bytes: &[u8], f: impl Fn(&str, &mut Vec<u8>)) -> Vec<u8> {
    let files = read_zip(bytes).unwrap();
    let mut owned: Vec<(String, Vec<u8>)> = files;
    for (n, d) in &mut owned {
        f(n, d);
    }
    let refs: Vec<(&str, &[u8])> = owned
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    write_zip(&refs).unwrap()
}

#[test]
fn ban_ma_bi_sua_bi_tu_choi() {
    let bytes = export_fast(Some(PW));
    let bad = rewrite(&bytes, |n, d| {
        if n == PAYLOAD {
            let i = d.len() - 5;
            d[i] ^= 1;
        }
    });
    assert!(matches!(import(&bad, APP, Some(PW)), Err(Error::Backup(_))));
}

#[test]
fn tep_khong_ma_hoa_bi_sua_bi_tu_choi() {
    let bytes = export(APP, 1, &entries(), None, NOW).unwrap();
    let bad = rewrite(&bytes, |n, d| {
        if n == "data/cai-dat.json" {
            d[2] ^= 1;
        }
    });
    assert_eq!(
        import(&bad, APP, None).unwrap_err(),
        Error::Backup("tệp bị hỏng hoặc bị sửa")
    );
    let extra = rewrite(&bytes, |_, _| {});
    let mut files = read_zip(&extra).unwrap();
    files.push(("la.txt".into(), b"x".to_vec()));
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    assert!(import(&write_zip(&refs).unwrap(), APP, None).is_err());
}

#[test]
fn sai_app_bi_tu_choi() {
    let bytes = export(APP, 1, &entries(), None, NOW).unwrap();
    assert_eq!(
        import(&bytes, "sound-db", None).unwrap_err(),
        Error::Backup("bản sao lưu của ứng dụng khác")
    );
    let enc = export_fast(Some(PW));
    assert!(import(&enc, "sound-db", Some(PW)).is_err());
}

#[test]
fn duong_dan_khong_an_toan_bi_tu_choi_ca_khi_xuat_va_nhap() {
    for p in [
        "../thoat.txt",
        "/tuyet-doi",
        "a/../../b",
        "a\\b",
        "C:/x",
        "",
        "a//b",
        "./a",
        MANIFEST,
        PAYLOAD,
        "a\nb",
    ] {
        let e = vec![Entry {
            path: p.into(),
            data: b"x".to_vec(),
        }];
        assert!(export(APP, 1, &e, None, NOW).is_err(), "xuất {p:?}");
    }
    // Zip độc tự dựng (không qua export) có đường dẫn thoát thư mục.
    let m = br#"{"format":"tsubak","v":1,"app":"qulythuchi","schema_version":1,"created_at":0,"encrypted":false,"entries":[{"path":"../x","size":1,"sha256":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}]}"#;
    let evil = write_zip(&[(MANIFEST, m), ("../x", b"x")]).unwrap();
    assert_eq!(
        import(&evil, APP, None).unwrap_err(),
        Error::Backup("đường dẫn trong tệp sao lưu không an toàn")
    );
}

#[test]
fn trung_ten_bi_tu_choi() {
    let e = vec![
        Entry {
            path: "a".into(),
            data: vec![1],
        },
        Entry {
            path: "a".into(),
            data: vec![2],
        },
    ];
    assert_eq!(
        export(APP, 1, &e, None, NOW).unwrap_err(),
        Error::Backup("tệp trùng tên")
    );
}

#[test]
fn khong_phai_tsubak() {
    assert!(inspect(b"khong phai zip").is_err());
    let z = write_zip(&[("a.txt", b"x")]).unwrap();
    assert_eq!(
        inspect(&z).unwrap_err(),
        Error::Backup("thiếu bản kê tsubak.json")
    );
    let wrong = write_zip(&[(MANIFEST, br#"{"format":"khac","v":1}"#)]).unwrap();
    assert!(inspect(&wrong).is_err());
}

#[test]
fn ghi_nguyen_tu() {
    let dir = std::env::temp_dir().join(format!("tsubak-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("sao-luu.tsubak");
    write_atomic(&p, b"lan 1").unwrap();
    write_atomic(&p, b"lan 2").unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"lan 2");
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(left.len(), 1, "không để lại tệp tạm");
    std::fs::remove_dir_all(&dir).unwrap();
}

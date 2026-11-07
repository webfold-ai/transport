//! `syncfold dd`: a dry run never touches the network.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::process::Command;

#[test]
fn dd_dry_run_to_tcp_does_not_connect() {
    let dir = std::env::temp_dir().join(format!("syncfold_dd_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("src.img");
    std::fs::write(&src, vec![7u8; 64 * 1024]).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let out = Command::new(env!("CARGO_BIN_EXE_syncfold"))
        .args([
            "dd",
            src.to_str().unwrap(),
            &format!("tcp://127.0.0.1:{port}"),
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("dry run"));
    match listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        Err(e) => panic!("accept: {e}"),
        Ok(_) => panic!("a dry run connected to the destination"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

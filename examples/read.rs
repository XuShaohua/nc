extern crate nc;

fn main() {
    #[cfg(target_os = "linux")]
    let fd = nc::openat(nc::AT_FDCWD, "/etc/passwd", nc::O_RDONLY, 0).expect("failed to open file");

    #[cfg(target_os = "freebsd")]
    let fd = nc::open("/etc/passwd", nc::O_RDONLY, 0).expect("failed to open file");

    let mut buf: [u8; 256] = [0; 256];
    loop {
        match nc::read(fd, &mut buf) {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                // FIXME(Shaohua): Read buf with len(n).
                if let Ok(s) = std::str::from_utf8(&buf) {
                    print!("s: {}", s);
                } else {
                    eprintln!("Failed to read buf as UTF-8!");
                    break;
                }
            }
            Err(errno) => {
                eprintln!("Failed to read, got errno: {}", errno);
                break;
            }
        }
    }

    let _ = nc::close(fd);
}


extern crate nc;

fn main() {
    let fd = nc::open("/etc/passwd", nc::O_RDONLY, 0)
        .expect("Failed to open file");

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
            },
            Err(errno) => {
                eprintln!("Failed to read, got errno: {}", errno);
                break;
            }
        }
    }

    nc::close(fd);
}

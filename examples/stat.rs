extern crate nc;

fn main() {
    let mut statbuf = nc::stat_t::default();
    match nc::fstatat(nc::AT_FDCWD, "/etc/passwd", &mut statbuf) {
        Ok(_) => {
            println!("s: {:?}", statbuf);
        }
        Err(errno) => {
            eprintln!("Failed to get file status, got errno: {}", errno);
        }
    }
}

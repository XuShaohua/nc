extern crate nc;

fn main() {
    let mut statbuf = nc::stat_t::default();
    let filepath = "/etc/passwd";

    #[cfg(target_arch = "x86_64")]
    match nc::newfstatat(nc::AT_FDCWD, filepath, &mut statbuf, 0) {
        Ok(_) => {
            println!("s: {:?}", statbuf);
        }
        Err(errno) => {
            eprintln!("Failed to get file status, got errno: {}", errno);
        }
    }
    #[cfg(any(target_arch = "arm", target_arch = "mips", target_arch = "powerpc64"))]
    match nc::stat(filepath, &mut statbuf) {
        Ok(_) => {
            println!("s: {:?}", statbuf);
        }
        Err(errno) => {
            eprintln!("Failed to get file status, got errno: {}", errno);
        }
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "mips",
        target_arch = "powerpc64"
    )))]
    match nc::fstatat(nc::AT_FDCWD, filepath, &mut statbuf) {
        Ok(_) => {
            println!("s: {:?}", statbuf);
        }
        Err(errno) => {
            eprintln!("Failed to get file status, got errno: {}", errno);
        }
    }
}

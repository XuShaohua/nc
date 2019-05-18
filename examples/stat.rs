
extern crate nc;

fn main() {
    match nc::stat("/etc/passwd") {
        Ok(statbuf) => {
            println!("s: {:?}", statbuf);
        },
        Err(errno) => {
            eprintln!("Failed to get file status, got errno: {}", errno);
        }
    }
}

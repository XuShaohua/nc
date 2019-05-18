
extern crate nc;

fn main() {
    let ret = nc::rename("/tmp/hello.rs", "/tmp/hello2.rs");
    match ret {
        Ok(_) => {
            println!("Rename file success!");
        },
        Err(errno) => {
            eprintln!("Failed to rename file, errno is: {}", errno);
        }
    }
}

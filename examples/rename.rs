extern crate nc;

fn main() {
    let ret = nc::renameat(nc::AT_FDCWD, "hello.rs", nc::AT_FDCWD, "world.rs");
    match ret {
        Ok(_) => {
            println!("Rename file success!");
        }
        Err(errno) => {
            eprintln!("Failed to rename file, errno is: {}", errno);
        }
    }
}

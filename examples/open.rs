extern crate nc;

fn main() {
    let path = "/tmp/hello.rs";
    let fd = nc::openat(
        nc::AT_FDCWD,
        path,
        nc::O_CREAT | nc::O_RDWR,
        nc::S_IRUSR | nc::S_IWUSR | nc::S_IRGRP | nc::S_IROTH,
    )
    .map_err(|err| eprintln!("err: {}", err))
    .expect("Failed to open file!");
    println!("fd: {:?}", fd);

    let msg = "fn main() { println!(\"Hello, world\");}";

    match nc::write(fd, msg.as_bytes()) {
        Ok(n) => {
            println!("Write {} chars", n);
        }
        Err(errno) => {
            eprintln!("Failed to write, got err: {}", errno);
        }
    }

    match nc::close(fd) {
        Ok(_) => {
            println!("File closed!");
        }
        Err(errno) => {
            eprintln!("Fail closed with errno: {}", errno);
        }
    }
}

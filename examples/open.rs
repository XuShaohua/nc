
extern crate nc;

fn main() {
    let path = "/tmp/hello.rs";
    let fd = nc::open(path,
                      nc::O_CREAT | nc::O_TRUNC,
                      nc::S_IRUSR | nc::S_IWUSR | nc::S_IRGRP | nc::S_IROTH)
        .expect("Failed to open file!");
    println!("fd: {:?}", fd);

    let msg = "fn main() { println!(\"Hello, world\");}";

    match nc::write(fd, msg.as_bytes()) {
        Ok(n) => {
            println!("Write {} chars", n);
        },
        Err(errno) => {
            eprintln!("Failed to write, got err: {}", errno);
        }
    }

    match nc::close(fd) {
        Ok(_) => {
            println!("File closed!");
        },
        Err(errno) => {
            eprintln!("Fail closed with errno: {}", errno);
        }
    }
}

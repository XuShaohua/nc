
extern crate nc;

fn main() {
    let msg = "hello, world\n";
    let nwrite = nc::write(-1, msg.as_bytes());
    match nwrite {
        Ok(n) => {
            println!("nwrite: {}", n);
        },
        Err(errno) => {
            println!("errno: {}", errno);
        }
    }

    let nwrite = nc::write(1, msg.as_bytes());
    match nwrite {
        Ok(n) => {
            println!("nwrite: {}", n);
        },
        Err(errno) => {
            println!("errno: {}", errno);
        }
    }
}

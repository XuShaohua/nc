
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
            if errno == nc::ERR_BADF {
                println!("Error: bad file descriptor");
            }
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

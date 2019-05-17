
extern crate nc;

fn main() {
    let msg = "hello, world\n";
    let nwrite = nc::write(-1, msg.as_bytes());
    println!("nwrite: {}", nwrite);
}

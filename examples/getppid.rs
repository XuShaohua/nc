extern crate nc;

fn main() {
    println!("ppid: {}", nc::getppid());
}

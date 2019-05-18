
extern crate nc;

fn main() {
    let pid = nc::getpid();
    let ret = nc::kill(pid, nc::SIGTERM);
    println!("ret: {:?}", ret);
}

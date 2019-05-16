
extern crate nc;

use nc::platform::c;

fn main() {
    println!("pid: {}", c::getpid());
}

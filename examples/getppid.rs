
extern crate nc;

use nc::platform::c;

fn main() {
    println!("ppid: {}", c::getppid());
}

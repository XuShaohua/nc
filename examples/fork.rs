
extern crate nc;

use nc::platform::c;

fn main() {
    let pid = c::fork();
    if pid == 0 {
        println!("parent process!");
    } else if pid < 0 {
        eprintln!("fork() error!");
    } else {
        println!("child process: {}", pid);
    }
}

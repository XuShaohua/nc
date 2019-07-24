
extern crate nc;

use nc::platform::c;

fn main() {
    let pid = c::fork();
    match pid {
        Ok(pid) => {
            if pid == 0 {
                println!("parent process!");
            } else if pid < 0 {
                eprintln!("fork() error!");
            } else {
                println!("child process: {}", pid);
                let args = [""];
                let env = [""];
                match nc::execve("/bin/ls", &args, &env) {
                    Ok(_) => {
                    },
                    Err(errno) => {
                        eprintln!("`ls` got err: {}", errno);
                    }
                }
            }
        },
        Err(errno) => {
            eprintln!("errno: {}", errno);
        }
    }
}

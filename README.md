
# nc
Process native call without `std`.

## Usage
Add this to `Cargo.toml`:
```toml
[dependencies]
nc = "0.1.1"
```

And add this to crate code:
```rust
extern crate nc;
```

## Examples
Get file stat:
```rust
let mut statbuf = nc::stat_t::default();
match nc::stat("/etc/passwd", &mut statbuf) {
    Ok(_) => println!("s: {:?}", statbuf),
    Err(errno) => eprintln!("Failed to get file status, got errno: {}", errno),
}
```

Fork process:
```rust
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
                Ok(_) => {},
                Err(errno) => eprintln!("`ls` got err: {}", errno),
            }
        }
    },
    Err(errno) => eprintln!("errno: {}", errno),
}
```

Kill self:
```rust
let pid = nc::getpid();
let ret = nc::kill(pid, nc::SIGTERM);
// Never reach here.
println!("ret: {:?}", ret);
```

## Related projects
* [nix][nix]
* [syscall][syscall]
* [relibc][relibc]

[syscall]: https://github.com/kmcallister/syscall.rs
[relibc]: https://gitlab.redox-os.org/redox-os/relibc.git
[nix]: https://github.com/nix-rust/nix

## License
This library is release in [Apache License](LICENSE).


nc
===

[![Build Status](https://travis-ci.com/xushaohua/nc.svg?branch=master)](https://travis-ci.com/xushaohua/nc)
[![Latest version](https://img.shields.io/crates/v/nc.svg)](https://crates.io/crates/nc)
[![Documentation](https://docs.rs/nc/badge.svg)](https://docs.rs/nc)
![Minimum rustc version](https://img.shields.io/badge/rustc-1.36+-yellow.svg)
![License](https://img.shields.io/crates/l/nc.svg)

Execute system call directly. `nc` do not depend on `std`.

- [Documentation](https://docs.rs/nc)
- [Release notes](https://github.com/xushaohua/nc/releases)

## Usage
Add this to `Cargo.toml`:
```toml
[dependencies]
nc = "0.4.7"
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
let pid = nc::fork();
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

## Stable version
For stable version of rustc, please install `gcc` first.
As `asm!` feature is unavailable in stable version. So we use a C library
instead to wrap syscall APIs.


## Related projects
* [nix][nix]
* [syscall][syscall]
* [relibc][relibc]

[syscall]: https://github.com/kmcallister/syscall.rs
[relibc]: https://gitlab.redox-os.org/redox-os/relibc.git
[nix]: https://github.com/nix-rust/nix

## License
This library is release in [Apache License](LICENSE).

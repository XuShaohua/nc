// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

pub type Syscalls = Vec<String>;

pub struct File {
    fd: i32,
}

impl File {
    pub fn open(path: &str) -> Result<File, crate::Errno> {
        let fd: i32 = crate::openat(crate::AT_FDCWD, path, crate::O_RDONLY, 0600)?;

        Ok(File { fd })
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if self.fd > -1 {
            let _ = crate::close(self.fd);
            self.fd = -1;
        }
    }
}

pub fn syscall_exists(name: &str) -> bool {
    let list = read_syscall_list().unwrap();
    for func_name in &list {
        if func_name.find(name).is_some() {
            return true;
        }
    }
    false
}

pub fn read_syscall_list() -> Result<Syscalls, crate::Errno> {
    let path = "/proc/kallsyms";
    let file = File::open(path)?;

    let mut list = Vec::new();
    const BUF_LEN: usize = 1024;
    let mut buf = [0u8; BUF_LEN];
    let mut line_str = Vec::with_capacity(BUF_LEN);
    loop {
        let buf_ptr = buf.as_mut_ptr() as usize;
        match crate::read(file.fd(), buf_ptr, BUF_LEN) {
            Err(errno) => return Err(errno),
            Ok(0) => break,
            Ok(n) => {
                let n = n as usize;
                for byte in &buf[0..n] {
                    if *byte == b'\n' {
                        // Check this line
                        let s = alloc::str::from_utf8(&line_str).map_err(|_| crate::EIO)?;
                        let mut iter = s.split_ascii_whitespace();
                        if iter.next().is_some() && iter.next() == Some("T") {
                            if let Some(func_name) = iter.next() {
                                if func_name.find("sys_").is_some() && iter.next().is_none() {
                                    println!("{}", func_name);
                                    list.push(func_name.to_string());
                                }
                            }
                        }

                        // Reset last line
                        line_str.clear();
                    } else {
                        line_str.push(*byte);
                    }
                }
            }
        }
    }

    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::{read_syscall_list, syscall_exists};

    #[test]
    fn test_read_syscall_list() {
        let list = read_syscall_list();
        assert!(list.is_ok());
        let list = list.unwrap();
        assert!(!list.is_empty());
    }

    #[test]
    fn test_syscall_exists() {
        let openat = "openat";
        assert!(syscall_exists(openat));
    }
}

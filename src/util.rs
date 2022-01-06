// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

pub struct Syscalls(Vec<String>);

struct File {
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

pub fn read_syscall_list() -> Result<Syscalls, crate::Errno> {
    let path = "/proc/kallsyms";
    let fd: i32 = crate::openat(crate::AT_FDCWD, path, crate::O_RDONLY, 0600)?;

    let mut list = Vec::new();
    const BUF_LEN: usize = 1024;
    let mut buf = [0u8; BUF_LEN];
    let mut line_str = Vec::with_capacity(BUF_LEN);
    loop {
        let buf_ptr = buf.as_mut_ptr() as usize;
        match crate::read(fd, buf_ptr, BUF_LEN) {
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
            Err(errno) => {
                crate::close(fd)?;
                return Err(errno);
            }
        }
    }

    crate::close(fd)?;
    Ok(Syscalls(list))
}

#[cfg(test)]
mod tests {
    use super::read_syscall_list;

    #[test]
    fn test_read_syscall_list() {
        let list = read_syscall_list();
        assert!(list.is_ok());
        let list = list.unwrap().0;
        assert!(!list.is_empty());
    }
}

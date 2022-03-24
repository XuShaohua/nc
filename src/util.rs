// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use alloc::collections::BTreeSet;

pub type Syscalls = BTreeSet<String>;

/// A simple wrapper to File IO.
///
/// File is closed when drop.
pub struct File {
    fd: i32,
}

impl File {
    /// Open file readonly.
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

/// Check syscall name exists in current system.
pub fn syscall_exists(name: &str) -> bool {
    let list = read_syscall_list().unwrap();
    list.contains(name)
}

fn parse_syscall_from_sym(s: &str) -> Option<String> {
    let mut iter = s.split_ascii_whitespace();
    if iter.next().is_some() && iter.next() == Some("T") {
        if let Some(func_name) = iter.next() {
            if let Some(pos) = func_name.find("sys_") {
                if func_name.len() > pos + 4 && iter.next().is_none() {
                    return Some(func_name[pos + 4..].to_string());
                }
            }
        }
    }
    None
}

/// Read syscall list from /proc.
pub fn read_syscall_list() -> Result<Syscalls, crate::Errno> {
    let path = "/proc/kallsyms";
    let file = File::open(path)?;

    let mut set = BTreeSet::new();
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
                    if *byte != b'\n' {
                        line_str.push(*byte);
                        continue;
                    }

                    // Check this line
                    let s = alloc::str::from_utf8(&line_str).map_err(|_| crate::EIO)?;
                    if let Some(func_name) = parse_syscall_from_sym(s) {
                        if !set.contains(&func_name) {
                            set.insert(func_name);
                        }
                    }

                    // Reset last line
                    line_str.clear();
                }
            }
        }
    }

    Ok(set)
}

pub fn pause() -> Result<(), crate::Errno> {
    // ppoll(0, 0, 0, 0) in C.
    #[cfg(target_arch = "aarch64")]
    let ret = crate::ppoll(
        &mut crate::pollfd_t::default(),
        0,
        &crate::timespec_t::default(),
        &crate::sigset_t::default(),
        0,
    )
    .map(drop);

    #[cfg(not(target_arch = "aarch64"))]
    let ret = crate::pause();

    ret
}

pub fn alarm(seconds: u32) -> Result<u32, crate::Errno> {
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    let remaining = {
        let mut it = crate::itimerval_t::default();
        it.it_value.tv_sec = seconds as isize;
        let mut old = crate::itimerval_t::default();
        crate::setitimer(crate::ITIMER_REAL, &mut it, &mut old)?;
        (old.it_value.tv_sec + !!old.it_value.tv_usec) as u32
    };

    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    let remaining = crate::alarm(seconds);

    Ok(remaining)
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

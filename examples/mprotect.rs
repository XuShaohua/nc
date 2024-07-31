// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

fn handle_segfault(sig: i32) {
    println!("Got segfault");
    assert_eq!(sig, nc::SIGSEGV);
}

fn main() {
    // Register SIGSEGV handler.
    let sa = nc::sigaction_t {
        sa_handler: handle_segfault as nc::sighandler_t,
        sa_flags: nc::SA_SIGINFO,
        ..nc::sigaction_t::default()
    };
    let ret = unsafe { nc::rt_sigaction(nc::SIGSEGV, Some(&sa), None) };
    assert!(ret.is_ok());

    // Initialize an anonymous mapping with 4 pages.
    let map_length = 4 * nc::PAGE_SIZE;
    #[cfg(target_arch = "arm")]
    let addr = unsafe {
        nc::mmap2(
            0,
            map_length,
            nc::PROT_READ | nc::PROT_WRITE,
            nc::MAP_PRIVATE | nc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    #[cfg(not(target_arch = "arm"))]
    let addr = unsafe {
        nc::mmap(
            0,
            map_length,
            nc::PROT_READ | nc::PROT_WRITE,
            nc::MAP_PRIVATE | nc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(addr.is_ok());
    let addr = addr.unwrap();

    // Set the third page readonly. And we will run into SIGSEGV when updating it.
    let ret = unsafe { nc::mprotect(addr + 2 * nc::PAGE_SIZE, nc::PAGE_SIZE, nc::PROT_READ) };
    assert!(ret.is_ok());

    for p in addr..(addr + map_length) {
        unsafe {
            *(p as *mut u8) = 42;
        }
    }

    let ret = unsafe { nc::munmap(addr, map_length) };
    assert!(ret.is_ok());
    unsafe { nc::exit(0) };
}

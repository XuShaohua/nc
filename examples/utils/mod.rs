pub fn pause() -> Result<(), nc::Errno> {
    // ppoll(0, 0, 0, 0) in C.
    #[cfg(target_arch = "aarch64")]
    let ret = nc::ppoll(
        &mut nc::pollfd_t::default(),
        0,
        &nc::timespec_t::default(),
        &nc::sigset_t::default(),
        0,
    )
    .map(drop);

    #[cfg(not(target_arch = "aarch64"))]
    let ret = nc::pause();

    ret
}

pub fn alarm(seconds: u32) -> Result<u32, nc::Errno> {
    #[cfg(target_arch = "aarch64")]
    let remaining = {
        let mut it = nc::itimerval_t::default();
        it.it_value.tv_sec = seconds as isize;
        let mut old = nc::itimerval_t::default();
        nc::setitimer(nc::ITIMER_REAL, &mut it, &mut old)?;
        (old.it_value.tv_sec + !!old.it_value.tv_usec) as u32
    };

    #[cfg(not(target_arch = "aarch64"))]
    let remaining = nc::alarm(seconds);

    Ok(remaining)
}

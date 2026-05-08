pub unsafe fn _lwp_kill(target: lwpid_t, signo: i32) -> Result<(), Errno> {
    let target = target as usize;
    let signo = signo as usize;
    unsafe { syscall2(SYS__LWP_KILL, target, signo).map(drop) }
}

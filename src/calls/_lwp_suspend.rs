pub unsafe fn _lwp_suspend(target: lwpid_t) -> Result<(), Errno> {
    let target = target as usize;
    unsafe { syscall1(SYS__LWP_SUSPEND, target).map(drop) }
}

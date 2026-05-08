pub unsafe fn _lwp_continue(target: lwpid_t) -> Result<(), Errno> {
    let target = target as usize;
    unsafe { syscall1(SYS__LWP_CONTINUE, target).map(drop) }
}

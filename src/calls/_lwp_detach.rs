pub unsafe fn _lwp_detach(target: lwpid_t) -> Result<(), Errno> {
    let target = target as usize;
    unsafe { syscall1(SYS__LWP_DETACH, target).map(drop) }
}

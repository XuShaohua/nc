pub unsafe fn _lwp_continue(target: lwpid_t) -> Result<(), Errno> {
    syscall0(SYS__LWP_CONTINUE).map(drop)
}

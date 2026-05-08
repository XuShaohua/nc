pub unsafe fn _lwp_getprivate() -> Result<uintptr_t, Errno> {
    unsafe { syscall0(SYS__LWP_GETPRIVATE) }
}

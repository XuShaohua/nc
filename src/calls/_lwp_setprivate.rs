pub unsafe fn _lwp_setprivate(ptr: uintptr_t) -> Result<(), Errno> {
    unsafe { syscall1(SYS__LWP_SETPRIVATE, ptr).map(drop) }
}

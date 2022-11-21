/// Create a new protection key.
pub unsafe fn pkey_alloc(flags: usize, init_val: usize) -> Result<i32, Errno> {
    syscall2(SYS_PKEY_ALLOC, flags, init_val).map(|ret| ret as i32)
}

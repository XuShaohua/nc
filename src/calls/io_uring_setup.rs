pub unsafe fn io_uring_setup(entries: u32, params: &mut io_uring_params_t) -> Result<i32, Errno> {
    let entries = entries as usize;
    let params_ptr = params as *mut io_uring_params_t as usize;
    syscall2(SYS_IO_URING_SETUP, entries, params_ptr).map(|ret| ret as i32)
}

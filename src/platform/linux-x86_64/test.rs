
macro_rules! syscall{
    ($fn_name:expr,
     $
}

syscall! (
    "open",
    SYS_OPEN,
    filename: &str,
    flags: i32,
    mode: mode_t,
    Result<i32, Errno>
);

pub fn open(filename: &str, flags: i32, mode: mode_t) -> Result<i32, Errno> {
    unsafe {
        let filename = CString::new(filename);
        let filename_ptr = filename.as_ptr() as usize;
        let flags = flags as usize;
        let mode = mode as usize;
        syscall3(SYS_OPEN, filename_ptr, flags, mode)
            .map(|ret| ret as i32)
    }
}

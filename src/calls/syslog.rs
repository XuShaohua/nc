/// Read and/or clear kernel message ring buffer.
pub unsafe fn syslog(action: i32, buf: &mut [u8]) -> Result<i32, Errno> {
    let action = action as usize;
    let buf_ptr = buf.as_mut_ptr() as usize;
    let buf_len = buf.len();
    syscall3(SYS_SYSLOG, action, buf_ptr, buf_len).map(|ret| ret as i32)
}

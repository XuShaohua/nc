/// System V message control operations.
pub unsafe fn __msgctl50(msqid: i32, cmd: i32, buf: &mut msqid_ds_t) -> Result<i32, Errno> {
    let msqid = msqid as usize;
    let cmd = cmd as usize;
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall3(SYS___MSGCTL50, msqid, cmd, buf_ptr).map(|ret| ret as i32) }
}

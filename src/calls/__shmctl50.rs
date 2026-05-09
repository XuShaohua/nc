/// System V shared memory control.
pub unsafe fn __shmctl50(shmid: i32, cmd: i32, buf: &mut shmid_ds_t) -> Result<i32, Errno> {
    let shmid = shmid as usize;
    let cmd = cmd as usize;
    let buf_ptr = core::ptr::from_mut(buf) as usize;
    unsafe { syscall3(SYS___SHMCTL50, shmid, cmd, buf_ptr).map(|ret| ret as i32) }
}

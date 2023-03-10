/// Unload kld files.
pub unsafe fn kldunload(file_id: i32) -> Result<i32, Errno> {
    let file_id = file_id as usize;
    syscall1(SYS_KLDUNLOAD, file_id).map(|ret| ret as i32)
}

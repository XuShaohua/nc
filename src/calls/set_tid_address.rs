/// Set pointer to thread ID.
pub unsafe fn set_tid_address(tid: &mut i32) -> Result<isize, Errno> {
    let tid_ptr = tid as *mut i32 as usize;
    syscall1(SYS_SET_TID_ADDRESS, tid_ptr).map(|ret| ret as isize)
}

/// Get thread id of current thread.
pub unsafe fn thr_self(id: &mut isize) -> Result<(), Errno> {
    let id_ptr = core::ptr::from_mut(id) as usize;
    unsafe { syscall1(SYS_THR_SELF, id_ptr).map(drop) }
}

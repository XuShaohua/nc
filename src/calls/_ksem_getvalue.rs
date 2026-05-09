/// Get the value of a semaphore
pub unsafe fn _ksem_getvalue(id: intptr_t, value: &mut u32) -> Result<(), Errno> {
    let id = id as usize;
    let value_ptr = core::ptr::from_mut(value) as usize;
    unsafe { syscall2(SYS__KSEM_GETVALUE, id, value_ptr).map(drop) }
}

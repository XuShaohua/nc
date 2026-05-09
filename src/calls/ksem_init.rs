/// Initialize an unamed semaphore.
pub unsafe fn ksem_init(value: u32, id: &mut semid_t) -> Result<(), Errno> {
    let value = value as usize;
    let id_ptr = core::ptr::from_mut(id) as usize;
    unsafe { syscall2(SYS_KSEM_INIT, value, id_ptr).map(drop) }
}

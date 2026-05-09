/// Initialize an unnamed semaphore.
pub unsafe fn _ksem_init(value: u32, id: &mut intptr_t) -> Result<(), Errno> {
    let value = value as usize;
    let id_ptr = core::ptr::from_mut(id) as usize;
    unsafe { syscall2(SYS__KSEM_INIT, value, id_ptr).map(drop) }
}

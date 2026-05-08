/// Decrement (lock) a semaphore.
pub unsafe fn ksem_trywait(id: semid_t) -> Result<(), Errno> {
    let id = id as usize;
    unsafe { syscall1(SYS_KSEM_TRYWAIT, id).map(drop) }
}

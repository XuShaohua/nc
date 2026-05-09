/// Decrement (lock) a semaphore.
pub unsafe fn sem_wait(sem: &mut sem_t) -> Result<(), Errno> {
    let sem_ptr = core::ptr::from_mut(sem) as usize;
    unsafe { syscall1(SYS_SEM_WAIT, sem_ptr).map(drop) }
}

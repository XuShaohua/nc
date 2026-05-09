/// Increment (unlock) a semaphore.
pub unsafe fn sem_post(sem: &mut sem_t) -> Result<(), Errno> {
    let sem_ptr = core::ptr::from_mut(sem) as usize;
    unsafe { syscall1(SYS_SEM_POST, sem_ptr).map(drop) }
}

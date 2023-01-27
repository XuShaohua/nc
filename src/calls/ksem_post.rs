/// Increment (unlock) a semaphore.
pub unsafe fn ksem_post(id: semid_t) -> Result<(), Errno> {
    let id = id as usize;
    syscall1(SYS_KSEM_POST, id).map(drop)
}
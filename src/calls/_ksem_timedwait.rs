/// Lock a semaphore.
pub unsafe fn _ksem_timedwait(id: intptr_t, abstime: &timespec_t) -> Result<(), Errno> {
    let id = id as usize;
    let abstime_ptr = core::ptr::from_ref(abstime) as usize;
    unsafe { syscall2(SYS__KSEM_TIMEDWAIT, id, abstime_ptr).map(drop) }
}

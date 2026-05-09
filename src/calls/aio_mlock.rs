/// Asynchronous mlock operation
pub unsafe fn aio_mlock(job: &mut aiocb_t) -> Result<(), Errno> {
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall1(SYS_AIO_MLOCK, job_ptr).map(drop) }
}

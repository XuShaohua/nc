/// Asynchronous write to a file (REALTIME)
pub unsafe fn aio_writev(job: &mut aiocb_t) -> Result<(), Errno> {
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall1(SYS_AIO_WRITEV, job_ptr).map(drop) }
}

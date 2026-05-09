/// Asynchronous read from a file (REALTIME)
pub unsafe fn aio_readv(job: &mut aiocb_t) -> Result<(), Errno> {
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall1(SYS_AIO_READV, job_ptr).map(drop) }
}

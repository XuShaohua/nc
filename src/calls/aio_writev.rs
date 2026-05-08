/// Asynchronous write to a file (REALTIME)
pub unsafe fn aio_writev(job: &mut aiocb_t) -> Result<(), Errno> {
    let job_ptr = job as *mut aiocb_t as usize;
    unsafe { syscall1(SYS_AIO_WRITEV, job_ptr).map(drop) }
}

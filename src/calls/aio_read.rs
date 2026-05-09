/// Asynchronous read from a file (REALTIME)
pub unsafe fn aio_read(job: &mut aiocb_t) -> Result<(), Errno> {
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall1(SYS_AIO_READ, job_ptr).map(drop) }
}

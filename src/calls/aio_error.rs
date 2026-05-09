/// Retrieve error status of asynchronous I/O operation
pub unsafe fn aio_error(job: &aiocb_t) -> Result<(), Errno> {
    let job_ptr = core::ptr::from_ref(job) as usize;
    unsafe { syscall1(SYS_AIO_ERROR, job_ptr).map(drop) }
}

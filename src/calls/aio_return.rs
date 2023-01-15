/// Retrieve return status of asynchronous I/O operation (REALTIME)
pub unsafe fn aio_return(job: &mut aiocb_t, job_ops: &mut aiocb_ops_t) -> Result<ssize_t, Errno> {
    let job_ptr = job as *mut aiocb_t as usize;
    let job_ops_ptr = job_ops as *mut aiocb_ops_t as usize;
    syscall2(SYS_AIO_RETURN, job_ptr, job_ops_ptr).map(|val| val as ssize_t)
}

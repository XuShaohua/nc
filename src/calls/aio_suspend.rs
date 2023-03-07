/// Suspend until asynchronous I/O operations or timeout complete (REALTIME)
pub unsafe fn aio_suspend(job: &aiocb_t, nent: i32, timeout: &timespec_t) -> Result<(), Errno> {
    let job_ptr = job as *const aiocb_t as usize;
    let nent = nent as usize;
    let timeout_ptr = timeout as *const timespec_t as usize;
    syscall3(SYS_AIO_SUSPEND, job_ptr, nent, timeout_ptr).map(drop)
}

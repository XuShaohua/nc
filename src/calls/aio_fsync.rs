/// Asynchronous file synchronization (REALTIME)
pub unsafe fn aio_fsync(op: i32, job: &mut aiocb_t) -> Result<(), Errno> {
    let op = op as usize;
    let job_ptr = core::ptr::from_mut(job) as usize;
    unsafe { syscall2(SYS_AIO_FSYNC, op, job_ptr).map(drop) }
}

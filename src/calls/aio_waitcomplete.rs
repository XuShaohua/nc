/// Wait for the next completion of an aio request
pub unsafe fn aio_waitcomplete(
    job: &mut aiocb_t,
    timeout: Option<&timespec_t>,
) -> Result<ssize_t, Errno> {
    let job_ptr = core::ptr::from_mut(job) as usize;
    let timeout_ptr =
        core::ptr::from_ref(core::mem::transmute::<Option<_>, &timespec_t>(timeout)) as usize;
    unsafe { syscall2(SYS_AIO_WAITCOMPLETE, job_ptr, timeout_ptr).map(|val| val as ssize_t) }
}

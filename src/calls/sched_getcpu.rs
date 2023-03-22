/// Determine CPU and NUMA node on which the calling thread is running.
pub unsafe fn sched_getcpu() -> Result<i32, Errno> {
    syscall0(SYS_SCHED_GETCPU).map(|val| val as i32)
}

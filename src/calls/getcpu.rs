/// Determine CPU and NUMA node on which the calling thread is running.
///
/// # Examples
///
/// ```
/// let mut cpu = 0;
/// let mut node = 0;
/// let mut cache = nc::getcpu_cache_t::default();
/// let ret = unsafe { nc::getcpu(&mut cpu, &mut node, &mut cache) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn getcpu(
    cpu: &mut u32,
    node: &mut u32,
    cache: &mut getcpu_cache_t,
) -> Result<(), Errno> {
    let cpu_ptr = core::ptr::from_mut(cpu) as usize;
    let node_ptr = core::ptr::from_mut(node) as usize;
    let cache_ptr = core::ptr::from_mut(cache) as usize;
    unsafe { syscall3(SYS_GETCPU, cpu_ptr, node_ptr, cache_ptr).map(drop) }
}

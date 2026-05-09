/// Set resource limit.
///
/// # Examples
///
/// ```
/// let rlimit = nc::rlimit_t {
///     rlim_cur: 128,
///     rlim_max: 128,
/// };
/// let ret = unsafe { nc::setrlimit(nc::RLIMIT_NOFILE, &rlimit) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn setrlimit(resource: i32, rlimit: &rlimit_t) -> Result<(), Errno> {
    let resource = resource as usize;
    let rlimit_ptr = core::ptr::from_ref(rlimit) as usize;
    unsafe { syscall2(SYS_SETRLIMIT, resource, rlimit_ptr).map(drop) }
}

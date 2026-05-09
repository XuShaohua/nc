/// Read/write system parameters.
pub unsafe fn _sysctl(args: &mut sysctl_args_t) -> Result<(), Errno> {
    let args_ptr = core::ptr::from_mut(args) as usize;
    unsafe { syscall1(SYS__SYSCTL, args_ptr).map(drop) }
}

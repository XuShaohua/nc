/// Get/set signal stack context.
pub unsafe fn __sigaltstack14(uss: &sigaltstack_t, uoss: &mut sigaltstack_t) -> Result<(), Errno> {
    let uss_ptr = core::ptr::from_ref(uss) as usize;
    let uoss_ptr = core::ptr::from_mut(uoss) as usize;
    unsafe { syscall2(SYS___SIGALTSTACK14, uss_ptr, uoss_ptr).map(drop) }
}

pub unsafe fn rtas(args: &mut rtas_args_t) -> Result<(), Errno> {
    let args_ptr = core::ptr::from_mut(args) as usize;
    unsafe { syscall1(SYS_RTAS, args_ptr).map(drop) }
}

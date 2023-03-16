/// Get user thread context.
pub unsafe fn getcontext(ctx: &mut ucontext_t) -> Result<(), Errno> {
    syscall1(SYS_GETCONTEXT, ctx).map(drop)
}

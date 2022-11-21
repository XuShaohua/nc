/// Return from signal handler and cleanup stack frame.
///
/// Never returns.
pub unsafe fn rt_sigreturn() {
    let _ = syscall0(SYS_RT_SIGRETURN);
}

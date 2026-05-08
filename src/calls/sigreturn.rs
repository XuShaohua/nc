/// Return from signal handler and cleanup stack frame.
/// Never returns.
pub unsafe fn sigreturn() {
    let _ = unsafe { syscall0(SYS_SIGRETURN) };
}

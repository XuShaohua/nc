/// Examine and change a signal action.
pub unsafe fn sigaction(
    sig: i32,
    act: &sigaction_t,
    old_act: &mut sigaction_t,
) -> Result<(), Errno> {
    let sig = sig as usize;
    let act_ptr = act as *const sigaction_t as usize;
    let old_act_ptr = old_act as *mut sigaction_t as usize;
    syscall3(SYS_SIGACTION, sig, act_ptr, old_act_ptr).map(drop)
}

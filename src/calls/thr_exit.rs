/// Terminate thread.
pub unsafe fn thr_exit(state: Option<&mut isize>) -> ! {
    let state_ptr = state.map_or(core::ptr::null_mut::<isize>() as usize, |state| {
        core::ptr::from_mut(state) as usize
    });
    unsafe {
        let _ret = syscall1(SYS_THR_EXIT, state_ptr).map(drop);
        core::hint::unreachable_unchecked();
    }
}

/// Creates a new kernel event queue and returns a descriptor.
pub unsafe fn kqueue() -> Result<i32, Errno> {
    unsafe { syscall0(SYS_KQUEUE).map(|val| val as i32) }
}

/// Set login class.
pub unsafe fn setloginclass(name: &str) -> Result<(), Errno> {
    let name = CString::new(name);
    let name_ptr = name.as_ptr() as usize;
    unsafe { syscall1(SYS_SETLOGINCLASS, name_ptr).map(drop) }
}

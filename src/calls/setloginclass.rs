/// Set login class.
pub unsafe fn setloginclass(name: &str) -> Result<(), Errno> {
    let name = CString::new(name.as_ref());
    let name_ptr = name.as_ptr() as usize;
    syscall1(SYS_SETLOGINCLASS, name_ptr).map(drop)
}

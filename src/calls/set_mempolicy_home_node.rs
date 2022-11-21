pub unsafe fn set_mempolicy_home_node(
    start: usize,
    len: usize,
    home_node: usize,
    flags: usize,
) -> Result<(), Errno> {
    syscall4(SYS_SET_MEMPOLICY_HOME_NODE, start, len, home_node, flags).map(drop)
}

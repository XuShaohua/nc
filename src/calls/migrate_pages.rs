/// Move all pages in a process to another set of nodes
pub unsafe fn migrate_pages(
    pid: pid_t,
    maxnode: usize,
    old_nodes: *const usize,
    new_nodes: *const usize,
) -> Result<isize, Errno> {
    let pid = pid as usize;
    let old_nodes = old_nodes as usize;
    let new_nodes = new_nodes as usize;
    syscall4(SYS_MIGRATE_PAGES, pid, maxnode, old_nodes, new_nodes).map(|ret| ret as isize)
}

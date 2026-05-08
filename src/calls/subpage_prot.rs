/// Define a subpage protection for an address range.
pub unsafe fn subpage_prot(addr: usize, len: usize, map: &mut u32) -> Result<(), Errno> {
    let map_ptr = core::ptr::from_mut(map) as usize;
    unsafe { syscall3(SYS_SUBPAGE_PROT, addr, len, map_ptr).map(drop) }
}

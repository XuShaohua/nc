pub unsafe fn listmount(req: &mnt_id_req_t, mnt_ids: &mut [u64], flags: u32) -> Result<(), Errno> {
    let req_ptr = core::ptr::from_ref(req) as usize;
    let mnt_ids_ptr = mnt_ids.as_mut_ptr() as usize;
    let nr_mnt_ids = mnt_ids.len();
    let flags = flags as usize;
    unsafe { syscall4(SYS_LISTMOUNT, req_ptr, mnt_ids_ptr, nr_mnt_ids, flags).map(drop) }
}

/// Set message queue attributes (realtime)
pub unsafe fn mq_setattr(
    mqdes: mqd_t,
    new_attr: Option<&mut mq_attr_t>,
    old_attr: Option<&mut mq_attr_t>,
) -> Result<(), Errno> {
    let mqdes = mqdes as usize;
    let new_attr_ptr = new_attr.map_or(0, |new_attr| core::ptr::from_mut(new_attr) as usize);
    let old_attr_ptr = old_attr.map_or(0, |old_attr| core::ptr::from_mut(old_attr) as usize);
    unsafe { syscall3(SYS_MQ_SETATTR, mqdes, new_attr_ptr, old_attr_ptr).map(drop) }
}

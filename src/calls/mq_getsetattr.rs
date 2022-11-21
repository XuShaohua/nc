/// Get/set message queue attributes
///
/// # Example
///
/// ```
/// let name = "nc-mq-getsetattr";
/// let ret = unsafe {
///     nc::mq_open(
///         name,
///         nc::O_CREAT | nc::O_RDWR,
///         (nc::S_IRUSR | nc::S_IWUSR) as nc::umode_t,
///         None,
///     )
/// };
/// assert!(ret.is_ok());
/// let mq_id = ret.unwrap();
///
/// let mut attr = nc::mq_attr_t::default();
/// let ret = unsafe { nc::mq_getsetattr(mq_id, None, Some(&mut attr)) };
/// assert!(ret.is_ok());
/// println!("attr: {:?}", attr);
///
/// let ret = unsafe { nc::close(mq_id) };
/// assert!(ret.is_ok());
/// let ret = unsafe { nc::mq_unlink(name) };
/// assert!(ret.is_ok());
/// ```
pub unsafe fn mq_getsetattr(
    mqdes: mqd_t,
    new_attr: Option<&mut mq_attr_t>,
    old_attr: Option<&mut mq_attr_t>,
) -> Result<mqd_t, Errno> {
    let mqdes = mqdes as usize;
    let new_attr_ptr = new_attr.map_or(0, |new_attr| new_attr as *mut mq_attr_t as usize);
    let old_attr_ptr = old_attr.map_or(0, |old_attr| old_attr as *mut mq_attr_t as usize);
    syscall3(SYS_MQ_GETSETATTR, mqdes, new_attr_ptr, old_attr_ptr).map(|ret| ret as mqd_t)
}

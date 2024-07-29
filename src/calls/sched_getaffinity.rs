/// Get a thread's CPU affinity mask.
///
/// # Examples
///
/// ```
/// use core::mem::size_of;
///
/// const SET_BITS: usize = 16;
/// #[repr(C)]
/// #[derive(Debug, Clone, Copy, PartialEq)]
/// struct CPUSet {
///     pub bits: [usize; SET_BITS],
/// }
///
/// impl Default for CPUSet {
///     fn default() -> Self {
///         CPUSet {
///             bits: [0; SET_BITS],
///         }
///     }
/// }
///
/// impl CPUSet {
///     #[inline]
///     pub const fn size() -> usize {
///         SET_BITS * size_of::<usize>()
///     }
///
///     #[inline]
///     pub const fn bits_size() -> usize {
///         CPUSet::size() * 8
///     }
///
///     pub fn set(&mut self, pos: usize) -> Result<(), nc::Errno> {
///         if pos >= CPUSet::bits_size() {
///             return Err(nc::EINVAL);
///         }
///         let bit_pos = pos / 8 / size_of::<usize>();
///         self.bits[bit_pos] |= 1 << (pos % (8 * size_of::<usize>()));
///         Ok(())
///     }
///
///     pub fn clear(&mut self, pos: usize) -> Result<(), nc::Errno> {
///         if pos >= CPUSet::bits_size() {
///             return Err(nc::EINVAL);
///         }
///         let bit_pos = pos / 8 / size_of::<usize>();
///         self.bits[bit_pos] &= !(1 << (pos % (8 * size_of::<usize>())));
///         Ok(())
///     }
///
///     pub fn is_set(&self, pos: usize) -> Result<bool, nc::Errno> {
///         if pos >= CPUSet::bits_size() {
///             return Err(nc::EINVAL);
///         }
///         let bit_pos = pos / 8 / size_of::<usize>();
///         let ret = self.bits[bit_pos] & (1 << (pos % (8 * size_of::<usize>())));
///
///         Ok(ret != 0)
///     }
///
///     pub fn as_ptr(&self) -> &[usize] {
///         &self.bits
///     }
///
///     pub fn as_mut_ptr(&mut self) -> &mut [usize] {
///         &mut self.bits
///     }
/// }
///
/// fn main() {
///     let mut set = CPUSet::default();
///     assert!(set.set(1).is_ok());
///     println!("set(1): {:?}", set.is_set(1));
///     assert!(set.set(2).is_ok());
///     assert!(set.clear(2).is_ok());
///     println!("set(2): {:?}", set.is_set(2));
///
///     let ret = unsafe { nc::sched_setaffinity(0, CPUSet::size(), set.as_ptr()) };
///     assert!(ret.is_ok());
///
///     let mut set2 = CPUSet::default();
///     let ret = unsafe { nc::sched_getaffinity(0, CPUSet::size(), set2.as_mut_ptr()) };
///     assert!(ret.is_ok());
///     assert_eq!(set, set2);
/// }
/// ```
pub unsafe fn sched_getaffinity(
    pid: pid_t,
    len: usize,
    user_mask: &mut [usize],
) -> Result<(), Errno> {
    let pid = pid as usize;
    let user_mask_ptr = user_mask.as_mut_ptr() as usize;
    syscall3(SYS_SCHED_GETAFFINITY, pid, len, user_mask_ptr).map(drop)
}

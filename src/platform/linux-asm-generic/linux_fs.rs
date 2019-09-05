#[repr(C)]
pub struct file_handle_ {
    pub handle_bytes: u32,
    pub handle_type: i32,
    /// file identifier
    pub f_handle: [u8; 0],
}

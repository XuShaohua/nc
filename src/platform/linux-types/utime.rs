use super::types::*;

#[repr(C)]
pub struct utimbuf_t {
    pub actime: time_t,
    pub modtime: time_t,
}

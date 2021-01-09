// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct file_handle_t {
    pub handle_bytes: u32,
    pub handle_type: i32,
    /// file identifier
    /// FIXME(Shaohua): Replace with a pointer
    pub f_handle: [u8; 0],
}

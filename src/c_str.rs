
extern crate core;
extern crate alloc;

use core::ops;
use alloc::boxed::Box;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct CString {
    inner: Box<[u8]>,
}

impl CString {
    pub fn new<T: Into<Vec<u8>>>(t: T) -> CString {
        unsafe {
            return CString::from_vec_unchecked(t.into());
        }
    }

    pub fn as_bytes_with_nul(&self) -> &[u8] {
        &self.inner
    }

    pub unsafe fn from_vec_unchecked(mut v: Vec<u8>) -> CString {
        v.reserve_exact(1);
        v.push(0);
        return CString {
            inner: v.into_boxed_slice(),
        };
    }

    pub const fn as_ptr(&self) -> *const u8 {
        let bytes = self.inner.as_ptr();
        return bytes;
        //return &*(bytes as *const [u8] as *const u8);
    }
}

/*
impl From<T> for CString where T: Into<Vec<v8>> {
    fn from<T: Into<Vec<v8>>>(v: T) -> Self {
        return CString::from_vec_unchecked(v);
    }
}
*/

//impl ops::Deref for CString {
//    type Target = [u8];
//
//    #[inline]
//    fn deref(&self) -> &[u8] {
//        return self.as_bytes_with_nul();
//    }
//
////    #[inline]
////    fn deref(&self) -> *const CStr {
////        unsafe {
////            return self.as_bytes_with_nul() as *const [u8] as *const CStr;
////        }
////    }
//}

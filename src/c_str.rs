extern crate alloc;
extern crate core;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write;
use core::mem;
use core::ops;
use core::ptr;

pub struct CString {
    inner: Box<[u8]>,
}

pub struct CStr {
    inner: [u8],
}

impl CString {
    pub fn new<T: Into<Vec<u8>>>(t: T) -> CString {
        let mut v = t.into();
        v.reserve_exact(1);
        v.push(0);
        CString {
            inner: v.into_boxed_slice(),
        }
    }

    pub fn with_capacity(cap: usize) -> CString {
        let mut v: Vec<u8> = vec![0; cap];
        v.reserve_exact(1);
        v.push(0);
        CString {
            inner: v.into_boxed_slice(),
        }
    }

    #[inline]
    const fn as_bytes_with_nul(&self) -> &[u8] {
        &self.inner
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.as_bytes_with_nul().len() - 1
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        // TODO(Shaohua): Check null bytes
        self.as_bytes_with_nul().len() == 0
    }

    pub fn strim_into_bytes(self) -> Vec<u8> {
        let mut vec = self.into_inner().into_vec();
        let mut nul_idx = 0;
        for v in &vec {
            if v == &0 {
                break;
            }
            nul_idx += 1;
        }
        vec.resize(nul_idx, 0);
        vec
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut vec = self.into_inner().into_vec();
        let _nul = vec.pop();
        vec
    }

    fn into_inner(self) -> Box<[u8]> {
        let this = mem::ManuallyDrop::new(self);
        unsafe { ptr::read(&this.inner) }
    }
}

impl CStr {
    pub const fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    pub const unsafe fn from_bytes_with_nul_unchecked(bytes: &[u8]) -> &CStr {
        &*(bytes as *const [u8] as *const CStr)
    }

    pub fn to_bytes(&self) -> &[u8] {
        let bytes = self.to_bytes_with_nul();
        &bytes[..bytes.len() - 1]
    }

    pub fn to_bytes_with_nul(&self) -> &[u8] {
        unsafe { &*(&self.inner as *const [u8]) }
    }
}

impl ops::Deref for CString {
    type Target = CStr;

    #[inline]
    fn deref(&self) -> &CStr {
        unsafe { CStr::from_bytes_with_nul_unchecked(self.as_bytes_with_nul()) }
    }
}

impl Drop for CString {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            *self.inner.get_unchecked_mut(0) = 0;
        }
    }
}

impl fmt::Debug for CString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl fmt::Debug for CStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for byte in self.to_bytes().iter() {
            f.write_char(*byte as char)?;
        }
        write!(f, "\"")
    }
}

impl From<CString> for Vec<u8> {
    #[inline]
    fn from(s: CString) -> Vec<u8> {
        s.into_bytes()
    }
}

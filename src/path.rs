// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use alloc::string::String;
use alloc::vec::Vec;

/// Reimplementation of `std::path::Path`.
pub struct Path {
    internal: [u8],
}

impl Path {
    #[inline]
    pub fn new<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Path {
        unsafe { &*(s.as_ref() as *const [u8] as *const Path) }
    }

    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.internal.len()
    }

    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.internal.is_empty()
    }
}

impl AsRef<Path> for str {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for String {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl From<&Path> for Vec<u8> {
    fn from(path: &Path) -> Vec<u8> {
        path.internal.to_vec()
    }
}

#[cfg(feature = "std")]
mod with_std {
    use std::borrow::Cow;
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStrExt;
    use std::path;

    use super::Path;

    impl AsRef<Path> for OsStr {
        #[inline]
        fn as_ref(&self) -> &Path {
            Path::new(self.as_bytes())
        }
    }
    impl AsRef<Path> for Cow<'_, OsStr> {
        #[inline]
        fn as_ref(&self) -> &Path {
            Path::new(self.as_bytes())
        }
    }
    impl AsRef<Path> for OsString {
        #[inline]
        fn as_ref(&self) -> &Path {
            Path::new(self.as_bytes())
        }
    }
    impl AsRef<Path> for path::PathBuf {
        fn as_ref(&self) -> &Path {
            self.as_path().as_ref()
        }
    }
    impl AsRef<Path> for path::Path {
        #[inline]
        fn as_ref(&self) -> &Path {
            Path::new(self.as_os_str().as_bytes())
        }
    }
}

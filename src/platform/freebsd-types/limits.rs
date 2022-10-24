// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From sys/sys/limits.h

use crate::{gid_t, uid_t, UINT_MAX};

// TODO(Shaohua): Check __CHAR_UNSIGNED__ macro
//#ifdef __CHAR_UNSIGNED__
// max value for a char
//pub const CHAR_MAX: i32 = UCHAR_MAX;
// min value for a char
//pub const CHAR_MIN: i32 = 0;
//#else
//pub const CHAR_MAX: i32 = SCHAR_MAX;
//pub const CHAR_MIN: i32 = SCHAR_MIN;
//#endif

/// max value for a `gid_t`
pub const GID_MAX: gid_t = UINT_MAX;

/// max value for a `uid_t`
pub const UID_MAX: uid_t = UINT_MAX;

// TODO(Shaohua): Update value type.
pub const MQ_PRIO_MAX: i32 = 64;

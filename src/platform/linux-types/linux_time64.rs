// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

pub type time64_t = i64;
pub type timeu64_t = u64;

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct timespec64_t {
    /// seconds
    pub tv_sec: time64_t,
    /// nanoseconds
    pub tv_nsec: isize,
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct itimerspec64_t {
    pub it_interval: timespec64_t,
    pub it_value: timespec64_t,
}

/// Parameters used to convert the timespec values:
pub const MSEC_PER_SEC: i64 = 1000;
pub const USEC_PER_MSEC: i64 = 1000;
pub const NSEC_PER_USEC: i64 = 1000;
pub const NSEC_PER_MSEC: i64 = 1_000_000;
pub const USEC_PER_SEC: i64 = 1_000_000;
pub const NSEC_PER_SEC: i64 = 1_000_000_000;
pub const FSEC_PER_SEC: i64 = 1_000_000_000_000_000;

/// Located here for timespec[64]_valid_strict
//#define TIME64_MAX			((s64)~((u64)1 << 63))
//#define KTIME_MAX			((s64)~((u64)1 << 63))
//#define KTIME_SEC_MAX			(KTIME_MAX / NSEC_PER_SEC)
//TODO(Shaohua):

/// Limits for settimeofday():
///
/// To prevent setting the time close to the wraparound point time setting
/// is limited so a reasonable uptime can be accomodated. Uptime of 30 years
/// should be really sufficient, which means the cutoff is 2232. At that
/// point the cutoff is just a small part of the larger problem.
pub const TIME_UPTIME_SEC_MAX: i64 = 30 * 365 * 24 * 3600;
//pub const TIME_SETTOD_SEC_MAX: i64 = 		(KTIME_SEC_MAX - TIME_UPTIME_SEC_MAX);

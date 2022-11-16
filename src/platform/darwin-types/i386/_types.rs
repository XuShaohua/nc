// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From `i386/_types.h`

pub type __darwin_intptr_t = isize;
pub type __darwin_natural_t = usize;

/// The rune type below is declared to be an `int` instead of the more natural
/// `unsigned long` or `long`.  Two things are happening here.  It is not
/// unsigned so that EOF (-1) can be naturally assigned to it and used.  Also,
/// it looks like 10646 will be a 31 bit standard.  This means that if your
/// ints cannot hold 32 bits, you will be in trouble.  The reason an int was
/// chosen over a long is that the is*() and to*() routines take ints (says
/// ANSI C), but they use __darwin_ct_rune_t instead of int.  By changing it
/// here, you lose a bit of ANSI conformance, but your programs will still
/// work.
///
/// NOTE: rune_t is not covered by ANSI nor other standards, and should not
/// be instantiated outside of lib/libc/locale.  Use wchar_t.  wchar_t and
/// rune_t must be the same type.  Also wint_t must be no narrower than
/// wchar_t, and should also be able to hold all members of the largest
/// character set plus one extra value (WEOF). wint_t must be at least 16 bits.
///
/// ct_rune_t
pub type __darwin_ct_rune_t = i32;

#[cfg(target_pointer_width = "64")]
/// ptr1 - ptr2
pub type __darwin_ptrdiff_t = isize;
#[cfg(target_pointer_width = "32")]
/// ptr1 - ptr2
pub type __darwin_ptrdiff_t = i32;

/// sizeof()
pub type __darwin_size_t = usize;

/// wchar_t
pub type __darwin_wchar_t = __darwin_ct_rune_t;

/// rune_t
pub type __darwin_rune_t = __darwin_wchar_t;

/// wint_t
pub type __darwin_wint_t = __darwin_ct_rune_t;

/// clock()
pub type __darwin_clock_t = usize;
/// socklen_t (duh)
pub type __darwin_socklen_t = u32;
/// byte count or error
pub type __darwin_ssize_t = isize;
/// time()
pub type __darwin_time_t = isize;

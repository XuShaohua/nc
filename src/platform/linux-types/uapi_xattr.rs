// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

// From uapi/linux/xattr.h

/// set value, fail if attr already exists
pub const XATTR_CREATE: i32 = 0x1;

/// set value, fail if attr does not exist
pub const XATTR_REPLACE: i32 = 0x2;

/// Namespaces
pub const XATTR_OS2_PREFIX: &'static str = "os2.";

pub const XATTR_MAC_OSX_PREFIX: &'static str = "osx.";

pub const XATTR_BTRFS_PREFIX: &'static str = "btrfs.";

pub const XATTR_HURD_PREFIX: &'static str = "gnu.";

pub const XATTR_SECURITY_PREFIX: &'static str = "security.";

pub const XATTR_SYSTEM_PREFIX: &'static str = "system.";

pub const XATTR_TRUSTED_PREFIX: &'static str = "trusted.";

pub const XATTR_USER_PREFIX: &'static str = "user.";

/// Security namespace
pub const XATTR_EVM_SUFFIX: &'static str = "evm";

pub const XATTR_IMA_SUFFIX: &'static str = "ima";
// TODO(Shaohua): Fix concat!() macro
//pub const XATTR_NAME_IMA: &'static str = XATTR_SECURITY_PREFIX + XATTR_IMA_SUFFIX;

pub const XATTR_SELINUX_SUFFIX: &'static str = "selinux";
//pub const XATTR_NAME_SELINUX: &'static str = XATTR_SECURITY_PREFIX + XATTR_SELINUX_SUFFIX;

pub const XATTR_SMACK_SUFFIX: &'static str = "SMACK64";
pub const XATTR_SMACK_IPIN: &'static str = "SMACK64IPIN";
pub const XATTR_SMACK_IPOUT: &'static str = "SMACK64IPOUT";
pub const XATTR_SMACK_EXEC: &'static str = "SMACK64EXEC";
pub const XATTR_SMACK_TRANSMUTE: &'static str = "SMACK64TRANSMUTE";
pub const XATTR_SMACK_MMAP: &'static str = "SMACK64MMAP";
//pub const XATTR_NAME_SMACK: &'static str = XATTR_SECURITY_PREFIX + XATTR_SMACK_SUFFIX;
//pub const XATTR_NAME_SMACKIPIN: &'static str = XATTR_SECURITY_PREFIX + XATTR_SMACK_IPIN;
//pub const XATTR_NAME_SMACKIPOUT: &'static str = XATTR_SECURITY_PREFIX + XATTR_SMACK_IPOUT;
//pub const XATTR_NAME_SMACKEXEC: &'static str = XATTR_SECURITY_PREFIX + XATTR_SMACK_EXEC;
//pub const XATTR_NAME_SMACKTRANSMUTE: &'static str = XATTR_SECURITY_PREFIX + XATTR_SMACK_TRANSMUTE;
//pub const XATTR_NAME_SMACKMMAP: &'static str = XATTR_SECURITY_PREFIX + XATTR_SMACK_MMAP;

pub const XATTR_APPARMOR_SUFFIX: &'static str = "apparmor";
//pub const XATTR_NAME_APPARMOR: &'static str = XATTR_SECURITY_PREFIX + XATTR_APPARMOR_SUFFIX;

pub const XATTR_CAPS_SUFFIX: &'static str = "capability";
//pub const XATTR_NAME_CAPS: &'static str = XATTR_SECURITY_PREFIX + XATTR_CAPS_SUFFIX;

pub const XATTR_POSIX_ACL_ACCESS: &'static str = "posix_acl_access";
//pub const XATTR_NAME_POSIX_ACL_ACCESS: &'static str = XATTR_SYSTEM_PREFIX + XATTR_POSIX_ACL_ACCESS;
pub const XATTR_POSIX_ACL_DEFAULT: &'static str = "posix_acl_default";
//pub const XATTR_NAME_POSIX_ACL_DEFAULT: &'static str =
//    XATTR_SYSTEM_PREFIX + XATTR_POSIX_ACL_DEFAULT;

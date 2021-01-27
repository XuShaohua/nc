// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

// From uapi/linux/reboot.h

/// Magic values required to use _reboot() system call.
#[allow(overflowing_literals)]
pub const LINUX_REBOOT_MAGIC1: i32 = 0xfee1dead;
pub const LINUX_REBOOT_MAGIC2: i32 = 672274793;
pub const LINUX_REBOOT_MAGIC2A: i32 = 85072278;
pub const LINUX_REBOOT_MAGIC2B: i32 = 369367448;
pub const LINUX_REBOOT_MAGIC2C: i32 = 537993216;

/// Commands accepted by the _reboot() system call.
///
/// RESTART     Restart system using default command and mode.
/// HALT        Stop OS and give system control to ROM monitor, if any.
/// CAD_ON      Ctrl-Alt-Del sequence causes RESTART command.
/// CAD_OFF     Ctrl-Alt-Del sequence sends SIGINT to init task.
/// POWER_OFF   Stop OS and remove all power from system, if possible.
/// RESTART2    Restart system using given command string.
/// SW_SUSPEND  Suspend system using software suspend if compiled in.
/// KEXEC       Restart system using a previously loaded Linux kernel
pub const LINUX_REBOOT_CMD_RESTART: u32 = 0x01234567;
pub const LINUX_REBOOT_CMD_HALT: u32 = 0xCDEF0123;
pub const LINUX_REBOOT_CMD_CAD_ON: u32 = 0x89ABCDEF;
pub const LINUX_REBOOT_CMD_CAD_OFF: u32 = 0x00000000;
pub const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321FEDC;
pub const LINUX_REBOOT_CMD_RESTART2: u32 = 0xA1B2C3D4;
pub const LINUX_REBOOT_CMD_SW_SUSPEND: u32 = 0xD000FCE2;
pub const LINUX_REBOOT_CMD_KEXEC: u32 = 0x45584543;

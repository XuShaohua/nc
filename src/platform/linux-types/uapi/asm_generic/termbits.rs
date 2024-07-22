// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `include/uapi/asm-generic/termbits.h`

pub type cc_t = u8;
pub type speed_t = u32;
pub type tcflag_t = u32;

pub const NCCS: usize = 19;

#[allow(clippy::module_name_repetitions)]
#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct termios_t {
    /// input mode flags
    pub c_iflag: tcflag_t,

    /// output mode flags
    pub c_oflag: tcflag_t,

    /// control mode flags
    pub c_cflag: tcflag_t,

    /// local mode flags
    pub c_lflag: tcflag_t,

    /// line discipline
    pub c_line: cc_t,

    /// control characters
    pub c_cc: [cc_t; NCCS],
}

#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct termios2_t {
    /// input mode flags
    pub c_iflag: tcflag_t,

    /// output mode flags
    pub c_oflag: tcflag_t,

    /// control mode flags
    pub c_cflag: tcflag_t,

    /// local mode flags
    pub c_lflag: tcflag_t,

    /// line discipline
    pub c_line: cc_t,

    /// control characters
    pub c_cc: [cc_t; NCCS],

    /// input speed
    pub c_ispeed: speed_t,

    /// output speed
    pub c_ospeed: speed_t,
}

#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct ktermios_t {
    /// input mode flags
    pub c_iflag: tcflag_t,

    /// output mode flags
    pub c_oflag: tcflag_t,

    /// control mode flags
    pub c_cflag: tcflag_t,

    /// local mode flags
    pub c_lflag: tcflag_t,

    /// line discipline
    pub c_line: cc_t,

    /// control characters
    pub c_cc: [cc_t; NCCS],

    /// input speed
    pub c_ispeed: speed_t,

    /// output speed
    pub c_ospeed: speed_t,
}

/// `c_cc` characters
pub const VINTR: cc_t = 0;
pub const VQUIT: cc_t = 1;
pub const VERASE: cc_t = 2;
pub const VKILL: cc_t = 3;
pub const VEOF: cc_t = 4;
pub const VTIME: cc_t = 5;
pub const VMIN: cc_t = 6;
pub const VSWTC: cc_t = 7;
pub const VSTART: cc_t = 8;
pub const VSTOP: cc_t = 9;
pub const VSUSP: cc_t = 10;
pub const VEOL: cc_t = 11;
pub const VREPRINT: cc_t = 12;
pub const VDISCARD: cc_t = 13;
pub const VWERASE: cc_t = 14;
pub const VLNEXT: cc_t = 15;
pub const VEOL2: cc_t = 16;

/// `c_iflag` bits
pub const IGNBRK: tcflag_t = 0o000_001;
pub const BRKINT: tcflag_t = 0o000_002;
pub const IGNPAR: tcflag_t = 0o000_004;
pub const PARMRK: tcflag_t = 0o000_010;
pub const INPCK: tcflag_t = 0o000_020;
pub const ISTRIP: tcflag_t = 0o000_040;
pub const INLCR: tcflag_t = 0o000_100;
pub const IGNCR: tcflag_t = 0o000_200;
pub const ICRNL: tcflag_t = 0o000_400;
pub const IUCLC: tcflag_t = 0o001_000;
pub const IXON: tcflag_t = 0o002_000;
pub const IXANY: tcflag_t = 0o004_000;
pub const IXOFF: tcflag_t = 0o010_000;
pub const IMAXBEL: tcflag_t = 0o020_000;
pub const IUTF8: tcflag_t = 0o040_000;

/// `c_oflag` bits
pub const OPOST: tcflag_t = 0o000_001;
pub const OLCUC: tcflag_t = 0o000_002;
pub const ONLCR: tcflag_t = 0o000_004;
pub const OCRNL: tcflag_t = 0o000_010;
pub const ONOCR: tcflag_t = 0o000_020;
pub const ONLRET: tcflag_t = 0o000_040;
pub const OFILL: tcflag_t = 0o000_100;
pub const OFDEL: tcflag_t = 0o000_200;
pub const NLDLY: tcflag_t = 0o000_400;
pub const NL0: tcflag_t = 0o000_000;
pub const NL1: tcflag_t = 0o000_400;
pub const CRDLY: tcflag_t = 0o003_000;
pub const CR0: tcflag_t = 0o000_000;
pub const CR1: tcflag_t = 0o001_000;
pub const CR2: tcflag_t = 0o002_000;
pub const CR3: tcflag_t = 0o003_000;
pub const TABDLY: tcflag_t = 0o014_000;
pub const TAB0: tcflag_t = 0o000_000;
pub const TAB1: tcflag_t = 0o00_4000;
pub const TAB2: tcflag_t = 0o010_000;
pub const TAB3: tcflag_t = 0o014_000;
pub const XTABS: tcflag_t = 0o014_000;
pub const BSDLY: tcflag_t = 0o020_000;
pub const BS0: tcflag_t = 0o000_000;
pub const BS1: tcflag_t = 0o020_000;
pub const VTDLY: tcflag_t = 0o040_000;
pub const VT0: tcflag_t = 0o000_000;
pub const VT1: tcflag_t = 0o040_000;
pub const FFDLY: tcflag_t = 0o100_000;
pub const FF0: tcflag_t = 0o000_000;
pub const FF1: tcflag_t = 0o100_000;

/// `c_cflag` bit meaning
pub const CBAUD: tcflag_t = 0o010_017;

/// hang up
pub const B0: tcflag_t = 0o000_000;
pub const B50: tcflag_t = 0o000_001;
pub const B75: tcflag_t = 0o000_002;
pub const B110: tcflag_t = 0o000_003;
pub const B134: tcflag_t = 0o000_004;
pub const B150: tcflag_t = 0o000_005;
pub const B200: tcflag_t = 0o000_006;
pub const B300: tcflag_t = 0o000_007;
pub const B600: tcflag_t = 0o000_010;
pub const B1200: tcflag_t = 0o000_011;
pub const B1800: tcflag_t = 0o000_012;
pub const B2400: tcflag_t = 0o000_013;
pub const B4800: tcflag_t = 0o000_014;
pub const B9600: tcflag_t = 0o000_015;
pub const B19200: tcflag_t = 0o000_016;
pub const B38400: tcflag_t = 0o000_017;
pub const EXTA: tcflag_t = B19200;
pub const EXTB: tcflag_t = B38400;
pub const CSIZE: tcflag_t = 0o000_060;
pub const CS5: tcflag_t = 0o000_000;
pub const CS6: tcflag_t = 0o000_020;
pub const CS7: tcflag_t = 0o000_040;
pub const CS8: tcflag_t = 0o000_060;
pub const CSTOPB: tcflag_t = 0o000_100;
pub const CREAD: tcflag_t = 0o000_200;
pub const PARENB: tcflag_t = 0o000_400;
pub const PARODD: tcflag_t = 0o001_000;
pub const HUPCL: tcflag_t = 0o002_000;
pub const CLOCAL: tcflag_t = 0o004_000;
pub const CBAUDEX: tcflag_t = 0o010_000;
pub const BOTHER: tcflag_t = 0o010_000;
pub const B57600: tcflag_t = 0o010_001;
pub const B115200: tcflag_t = 0o010_002;
pub const B230400: tcflag_t = 0o010_003;
pub const B460800: tcflag_t = 0o010_004;
pub const B500000: tcflag_t = 0o010_005;
pub const B576000: tcflag_t = 0o010_006;
pub const B921600: tcflag_t = 0o010_007;
pub const B1000000: tcflag_t = 0o010_010;
pub const B1152000: tcflag_t = 0o010_011;
pub const B1500000: tcflag_t = 0o010_012;
pub const B2000000: tcflag_t = 0o010_013;
pub const B2500000: tcflag_t = 0o010_014;
pub const B3000000: tcflag_t = 0o010_015;
pub const B3500000: tcflag_t = 0o010_016;
pub const B4000000: tcflag_t = 0o010_017;
/// input baud rate
pub const CIBAUD: tcflag_t = 0o02_003_600_000;
/// mark or space (stick) parity
pub const CMSPAR: tcflag_t = 0o10_000_000_000;
/// flow control
pub const CRTSCTS: tcflag_t = 0o20_000_000_000;

/// Shift from CBAUD to CIBAUD
pub const IBSHIFT: tcflag_t = 16;

/// `c_lflag` bits
pub const ISIG: tcflag_t = 0o000_001;
pub const ICANON: tcflag_t = 0o000_002;
pub const XCASE: tcflag_t = 0o000_004;
pub const ECHO: tcflag_t = 0o000_010;
pub const ECHOE: tcflag_t = 0o000_020;
pub const ECHOK: tcflag_t = 0o000_040;
pub const ECHONL: tcflag_t = 0o000_100;
pub const NOFLSH: tcflag_t = 0o000_200;
pub const TOSTOP: tcflag_t = 0o000_400;
pub const ECHOCTL: tcflag_t = 0o001_000;
pub const ECHOPRT: tcflag_t = 0o002_000;
pub const ECHOKE: tcflag_t = 0o004_000;
pub const FLUSHO: tcflag_t = 0o010_000;
pub const PENDIN: tcflag_t = 0o040_000;
pub const IEXTEN: tcflag_t = 0o100_000;
pub const EXTPROC: tcflag_t = 0o200_000;

/// `tcflow()` and TCXONC use these
pub const TCOOFF: i32 = 0;
pub const TCOON: i32 = 1;
pub const TCIOFF: i32 = 2;
pub const TCION: i32 = 3;

/// `tcflush()` and TCFLSH use these
pub const TCIFLUSH: i32 = 0;
pub const TCOFLUSH: i32 = 1;
pub const TCIOFLUSH: i32 = 2;

/// tcsetattr uses these
pub const TCSANOW: i32 = 0;
pub const TCSADRAIN: i32 = 1;
pub const TCSAFLUSH: i32 = 2;

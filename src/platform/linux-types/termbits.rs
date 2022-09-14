// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

pub type cc_t = u8;
pub type speed_t = u32;
pub type tcflag_t = u32;

pub const NCCS: usize = 19;

#[allow(clippy::module_name_repetitions)]
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
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
#[derive(Default, Debug, Clone, Copy)]
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
#[derive(Default, Debug, Clone, Copy)]
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
pub const VINTR: i32 = 0;
pub const VQUIT: i32 = 1;
pub const VERASE: i32 = 2;
pub const VKILL: i32 = 3;
pub const VEOF: i32 = 4;
pub const VTIME: i32 = 5;
pub const VMIN: i32 = 6;
pub const VSWTC: i32 = 7;
pub const VSTART: i32 = 8;
pub const VSTOP: i32 = 9;
pub const VSUSP: i32 = 10;
pub const VEOL: i32 = 11;
pub const VREPRINT: i32 = 12;
pub const VDISCARD: i32 = 13;
pub const VWERASE: i32 = 14;
pub const VLNEXT: i32 = 15;
pub const VEOL2: i32 = 16;

/// `c_iflag` bits
pub const IGNBRK: i32 = 0o000_001;
pub const BRKINT: i32 = 0o000_002;
pub const IGNPAR: i32 = 0o000_004;
pub const PARMRK: i32 = 0o000_010;
pub const INPCK: i32 = 0o000_020;
pub const ISTRIP: i32 = 0o000_040;
pub const INLCR: i32 = 0o000_100;
pub const IGNCR: i32 = 0o000_200;
pub const ICRNL: i32 = 0o000_400;
pub const IUCLC: i32 = 0o001_000;
pub const IXON: i32 = 0o002_000;
pub const IXANY: i32 = 0o004_000;
pub const IXOFF: i32 = 0o010_000;
pub const IMAXBEL: i32 = 0o020_000;
pub const IUTF8: i32 = 0o040_000;

/// `c_oflag` bits
pub const OPOST: i32 = 0o000_001;
pub const OLCUC: i32 = 0o000_002;
pub const ONLCR: i32 = 0o000_004;
pub const OCRNL: i32 = 0o000_010;
pub const ONOCR: i32 = 0o000_020;
pub const ONLRET: i32 = 0o000_040;
pub const OFILL: i32 = 0o000_100;
pub const OFDEL: i32 = 0o000_200;
pub const NLDLY: i32 = 0o000_400;
pub const NL0: i32 = 0o000_000;
pub const NL1: i32 = 0o000_400;
pub const CRDLY: i32 = 0o003_000;
pub const CR0: i32 = 0o000_000;
pub const CR1: i32 = 0o001_000;
pub const CR2: i32 = 0o002_000;
pub const CR3: i32 = 0o003_000;
pub const TABDLY: i32 = 0o014_000;
pub const TAB0: i32 = 0o000_000;
pub const TAB1: i32 = 0o00_4000;
pub const TAB2: i32 = 0o010_000;
pub const TAB3: i32 = 0o014_000;
pub const XTABS: i32 = 0o014_000;
pub const BSDLY: i32 = 0o020_000;
pub const BS0: i32 = 0o000_000;
pub const BS1: i32 = 0o020_000;
pub const VTDLY: i32 = 0o040_000;
pub const VT0: i32 = 0o000_000;
pub const VT1: i32 = 0o040_000;
pub const FFDLY: i32 = 0o100_000;
pub const FF0: i32 = 0o000_000;
pub const FF1: i32 = 0o100_000;

/// `c_cflag` bit meaning
pub const CBAUD: i32 = 0o010_017;

/// hang up
pub const B0: i32 = 0o000_000;
pub const B50: i32 = 0o000_001;
pub const B75: i32 = 0o000_002;
pub const B110: i32 = 0o000_003;
pub const B134: i32 = 0o000_004;
pub const B150: i32 = 0o000_005;
pub const B200: i32 = 0o000_006;
pub const B300: i32 = 0o000_007;
pub const B600: i32 = 0o000_010;
pub const B1200: i32 = 0o000_011;
pub const B1800: i32 = 0o000_012;
pub const B2400: i32 = 0o000_013;
pub const B4800: i32 = 0o000_014;
pub const B9600: i32 = 0o000_015;
pub const B19200: i32 = 0o000_016;
pub const B38400: i32 = 0o000_017;
pub const EXTA: i32 = B19200;
pub const EXTB: i32 = B38400;
pub const CSIZE: i32 = 0o000_060;
pub const CS5: i32 = 0o000_000;
pub const CS6: i32 = 0o000_020;
pub const CS7: i32 = 0o000_040;
pub const CS8: i32 = 0o000_060;
pub const CSTOPB: i32 = 0o000_100;
pub const CREAD: i32 = 0o000_200;
pub const PARENB: i32 = 0o000_400;
pub const PARODD: i32 = 0o001_000;
pub const HUPCL: i32 = 0o002_000;
pub const CLOCAL: i32 = 0o004_000;
pub const CBAUDEX: i32 = 0o010_000;
pub const BOTHER: i32 = 0o010_000;
pub const B57600: i32 = 0o010_001;
pub const B115200: i32 = 0o010_002;
pub const B230400: i32 = 0o010_003;
pub const B460800: i32 = 0o010_004;
pub const B500000: i32 = 0o010_005;
pub const B576000: i32 = 0o010_006;
pub const B921600: i32 = 0o010_007;
pub const B1000000: i32 = 0o010_010;
pub const B1152000: i32 = 0o010_011;
pub const B1500000: i32 = 0o010_012;
pub const B2000000: i32 = 0o010_013;
pub const B2500000: i32 = 0o010_014;
pub const B3000000: i32 = 0o010_015;
pub const B3500000: i32 = 0o010_016;
pub const B4000000: i32 = 0o010_017;
/// input baud rate
pub const CIBAUD: i32 = 0o02_003_600_000;
/// mark or space (stick) parity
#[allow(overflowing_literals)]
pub const CMSPAR: i32 = 0o10_000_000_000;
/// flow control
#[allow(overflowing_literals)]
pub const CRTSCTS: i32 = 0o20_000_000_000;

/// Shift from CBAUD to CIBAUD
pub const IBSHIFT: i32 = 16;

/// `c_lflag` bits
pub const ISIG: i32 = 0o000_001;
pub const ICANON: i32 = 0o000_002;
pub const XCASE: i32 = 0o000_004;
pub const ECHO: i32 = 0o000_010;
pub const ECHOE: i32 = 0o000_020;
pub const ECHOK: i32 = 0o000_040;
pub const ECHONL: i32 = 0o000_100;
pub const NOFLSH: i32 = 0o000_200;
pub const TOSTOP: i32 = 0o000_400;
pub const ECHOCTL: i32 = 0o001_000;
pub const ECHOPRT: i32 = 0o002_000;
pub const ECHOKE: i32 = 0o004_000;
pub const FLUSHO: i32 = 0o010_000;
pub const PENDIN: i32 = 0o040_000;
pub const IEXTEN: i32 = 0o100_000;
pub const EXTPROC: i32 = 0o200_000;

/// tcflow() and TCXONC use these
pub const TCOOFF: i32 = 0;
pub const TCOON: i32 = 1;
pub const TCIOFF: i32 = 2;
pub const TCION: i32 = 3;

/// tcflush() and TCFLSH use these
pub const TCIFLUSH: i32 = 0;
pub const TCOFLUSH: i32 = 1;
pub const TCIOFLUSH: i32 = 2;

/// tcsetattr uses these
pub const TCSANOW: i32 = 0;
pub const TCSADRAIN: i32 = 1;
pub const TCSAFLUSH: i32 = 2;

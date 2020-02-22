use core::mem::size_of;

/// ioctl command encoding: 32 bits total, command in lower 16 bits,
/// size of the parameter structure in the lower 14 bits of the
/// upper 16 bits.
/// Encoding the size of the parameter structure in the ioctl request
/// is useful for catching programs compiled with old versions
/// and to avoid overwriting user space outside the user buffer area.
/// The highest 2 bits are reserved for indicating the ``access mode''.
/// NOTE: This limits the max parameter size to 16kB -1 !

/// The following is for compatibility across the various Linux
/// platforms.  The generic ioctl numbering scheme doesn't really enforce
/// a type field.  De facto, however, the top 8 bits of the lower 16
/// bits are indeed used as a type field, so we might just as well make
/// this explicit here.  Please be sure to use the decoding macros
/// below from now on.

pub const IOC_NRBITS: i32 = 8;
pub const IOC_TYPEBITS: i32 = 8;

/// Let any architecture override either of the following before including this file.

pub const IOC_SIZEBITS: i32 = 14;

pub const IOC_DIRBITS: i32 = 2;

pub const IOC_NRMASK: i32 = (1 << IOC_NRBITS) - 1;
pub const IOC_TYPEMASK: i32 = (1 << IOC_TYPEBITS) - 1;
pub const IOC_SIZEMASK: i32 = (1 << IOC_SIZEBITS) - 1;
pub const IOC_DIRMASK: i32 = (1 << IOC_DIRBITS) - 1;

pub const IOC_NRSHIFT: i32 = 0;
pub const IOC_TYPESHIFT: i32 = IOC_NRSHIFT + IOC_NRBITS;
pub const IOC_SIZESHIFT: i32 = IOC_TYPESHIFT + IOC_TYPEBITS;
pub const IOC_DIRSHIFT: i32 = IOC_SIZESHIFT + IOC_SIZEBITS;

/// Direction bits, which any architecture can choose to override
/// before including this file.
///
/// NOTE: _IOC_WRITE means userland is writing and kernel is
/// reading. _IOC_READ means userland is reading and kernel is writing.

pub const IOC_NONE: i32 = 0;

pub const IOC_WRITE: i32 = 1;

pub const IOC_READ: i32 = 2;

#[inline]
pub const fn IOC(dir: i32, type_: char, nr: i32, size: i32) -> i32 {
    let type_ = type_ as i32;
    (dir << IOC_DIRSHIFT) | (type_ << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

#[inline]
pub const fn IOC_TYPECHECK<T>() -> i32 {
    size_of::<T>() as i32
}

/// Used to create numbers.
///
/// NOTE: _IOW means userland is writing and kernel is reading. _IOR
/// means userland is reading and kernel is writing.
#[inline]
pub const fn IO(type_: char, nr: i32) -> i32 {
    IOC(IOC_NONE, type_, nr, 0)
}

#[inline]
pub const fn IOR<T>(type_: char, nr: i32) -> i32 {
    IOC(IOC_READ, type_, nr, IOC_TYPECHECK::<T>())
}

#[inline]
pub const fn IOW<T>(type_: char, nr: i32) -> i32 {
    IOC(IOC_WRITE, type_, nr, IOC_TYPECHECK::<T>())
}

#[inline]
pub const fn IOWR<T>(type_: char, nr: i32) -> i32 {
    IOC(IOC_READ | IOC_WRITE, type_, nr, IOC_TYPECHECK::<T>())
}

#[inline]
pub const fn IOR_BAD<T>(type_: char, nr: i32) -> i32 {
    IOC(IOC_READ, type_, nr, IOC_TYPECHECK::<T>())
}

#[inline]
pub const fn IOW_BAD<T>(type_: char, nr: i32) -> i32 {
    IOC(IOC_WRITE, type_, nr, IOC_TYPECHECK::<T>())
}

#[inline]
pub const fn IOWR_BAD<T>(type_: char, nr: i32) -> i32 {
    IOC(IOC_READ | IOC_WRITE, type_, nr, IOC_TYPECHECK::<T>())
}

/// used to decode ioctl numbers..
#[inline]
pub const fn IOC_DIR(nr: i32) -> i32 {
    (nr >> IOC_DIRSHIFT) & IOC_DIRMASK
}

#[inline]
pub const fn IOC_TYPE(nr: i32) -> i32 {
    nr >> IOC_TYPESHIFT & IOC_TYPEMASK
}

#[inline]
pub const fn IOC_NR(nr: i32) -> i32 {
    (nr >> IOC_NRSHIFT) & IOC_NRMASK
}

#[inline]
pub const fn IOC_SIZE(nr: i32) -> i32 {
    nr >> IOC_SIZESHIFT & IOC_SIZEMASK
}

/// ...and for the drivers/sound files...

pub const IOC_IN: i32 = IOC_WRITE << IOC_DIRSHIFT;
pub const IOC_OUT: i32 = IOC_READ << IOC_DIRSHIFT;
pub const IOC_INOUT: i32 = (IOC_WRITE | IOC_READ) << IOC_DIRSHIFT;
pub const IOCSIZE_MASK: i32 = IOC_SIZEMASK << IOC_SIZESHIFT;
pub const IOCSIZE_SHIFT: i32 = IOC_SIZESHIFT;

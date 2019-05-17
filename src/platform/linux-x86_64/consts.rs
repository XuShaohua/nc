
use super::types::mode_t;

pub const S_IRUSR: mode_t = 0400;
pub const S_IWUSR: mode_t = 0200;
pub const S_IXUSR: mode_t = 0100;
pub const S_IRWXU: mode_t = S_IRUSR | S_IWUSR | S_IXUSR;
pub const S_IRGRP: mode_t = S_IRUSR >> 3;
pub const S_IWGRP: mode_t = S_IWUSR >> 3;
pub const S_IXGRP: mode_t = S_IXUSR >> 3;
pub const S_IRWXG: mode_t = S_IRWXU >> 3;
pub const S_IROTH: mode_t = S_IRGRP >> 3;
pub const S_IWOTH: mode_t = S_IWGRP >> 3;
pub const S_IXOTH: mode_t = S_IXGRP >> 3;
pub const S_IRWXO: mode_t = S_IRWXG >> 3;


pub const O_RDONLY: i32 = 00;
pub const O_WRONLY: i32 = 01;
pub const O_RDWR: i32 = 02;
pub const O_CREAT: i32 = 0100;
pub const O_EXCL: i32 = 0200;
pub const O_NOCTTY: i32 = 0400;
pub const O_TRUNC: i32 = 01000;
pub const O_APPEND: i32 = 02000;
pub const O_NONBLOCK: i32 = 04000;
pub const O_SYNC: i32 = 04010000;
pub const O_ASYNC: i32 = 020000;


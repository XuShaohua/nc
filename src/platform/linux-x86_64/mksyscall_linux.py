#!/usr/bin/env python3
# Copyright (c) 2019 Xu Shaohua <xushaohua2016@outlook.com>. All rights reserved.
# Use of this source is governed by Apache License that can be found
# in the LICENSE file.

import re
import sys

primitive_types = (
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "byte",
    "bool",
    "be32_t",
    "blksize_t",
    "blkcnt_t",
    "clock_t",
    "clockid_t",
    "daddr_t",
    "dev_t",
    "gid_t",
    "ino_t",
    "key_t",
    "loff_t",
    "mode_t",
    "mqd_t",
    "msglen_t",
    "msgqnum_t",
    "nfds_t",
    "nlink_t",
    "off_t",
    "pid_t",
    "poll_t",
    "rwf_t",
    "sa_family_t",
    "sigset_t",
    "size_t",
    "socklen_t",
    "ssize_t",
    "time_t",
    "timer_t",
    "uid_t",
    "umode_t",
    "rlimit_t",
    "shmatt_t",
    "suseconds_t",
)

def print_syscall(line):
    pattern = re.compile(r"sys (?P<func_name>\()")
    m = pattern.match(line)
    print(m)

def main():
    if len(sys.argv) != 2:
        print("Usage: %s template-file" % sys.args[0])
        sys.exit(1)

    with open(sys.argv[1]) as fh:
        for line in fh:
            if line.startswith("sys "):
                print_syscall(line)
            else:
                print(line, end="")


if __name__ == "__main__":
    main()

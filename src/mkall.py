#!/usr/bin/env python3
# Copyright (c) 2019 Xu Shaohua <xushaohua2016@outlook.com>. All rights reserved.
# Use of this source is governed by General Public License that can be found
# in the LICENSE file.

import os
import subprocess
import sys


def install_debian_headers():
    pkgs = [
        #"linux-libc-dev-alpha-cross",
        "linux-libc-dev-amd64-cross",
        "linux-libc-dev-arm64-cross",
        "linux-libc-dev-armel-cross",
        "linux-libc-dev-armhf-cross",
        #"linux-libc-dev-hppa-cross",
        "linux-libc-dev-i386-cross",
        #"linux-libc-dev-m68k-cross",
        "linux-libc-dev-mips-cross",
        "linux-libc-dev-mips64-cross",
        "linux-libc-dev-mips64el-cross",
        #"linux-libc-dev-mips64r6-cross",
        #"linux-libc-dev-mips64r6el-cross",
        "linux-libc-dev-mipsel-cross",
        #"linux-libc-dev-mipsn32-cross",
        #"linux-libc-dev-mipsn32el-cross",
        #"linux-libc-dev-mipsn32r6-cross",
        #"linux-libc-dev-mipsn32r6el-cross",
        #"linux-libc-dev-mipsr6-cross",
        #"linux-libc-dev-mipsr6el-cross",
        "linux-libc-dev-powerpc-cross",
        "linux-libc-dev-ppc64-cross",
        "linux-libc-dev-ppc64el-cross",
        #"linux-libc-dev-riscv64-cross",
        "linux-libc-dev-s390x-cross",
        #"linux-libc-dev-sh4-cross",
        "linux-libc-dev-sparc64-cross",
        #"linux-libc-dev-x32-cross",
    ]
    cmd = [
        "sudo",
        "apt",
        "install",
        "-y",
    ]
    cmd.extend(pkgs)

    p = subprocess.run(cmd)
    print(p)

def get_errno_header(os, arch):
    if os == "linux":
        if arch == "aarch64":
            return "/usr/aarch64-linux-gnu/include/asm/errno.h"
        elif arch == "armel":
            return "/usr/arm-linux-gnueabi/include/asm/errno.h"
        elif arch == "armhf":
            return "/usr/arm-linux-gnueabihf/include/asm/errno.h"
        elif arch == "mips":
            return "/usr/mips-linux-gnu/include/asm/errno.h"
        elif arch == "mips64":
            return "/usr/mips64-linux-gnuabi64/include/asm/errno.h"
        elif arch == "powerpc64":
            return "/usr/powerpc64-linux-gnu/include/asm/errno.h"
        elif arch == "powerpc":
            return "/usr/powerpc-linux-gnu/include/asm/errno.h"
        elif arch == "s390x":
            return "/usr/s390x-linux-gnu/include/asm/errno.h"
        elif arch == "sparc64":
            return "/usr/sparc64-linux-gnu/include/asm/errno.h"
        elif arch == "x86":
            return "/usr/i686-linux-gnu/include/asm/errno.h"
        elif arch == "x86_64":
            return "/usr/x86_64-linux-gnu/include/asm/errno.h"
    return "/usr/include/asm/errno.h"

def get_sysno_header(os, arch):
    if os == "linux":
        if arch == "aarch64":
            return "/usr/aarch64-linux-gnu/include/asm/unistd.h"
        elif arch == "armel":
            return "/usr/arm-linux-gnueabi/include/asm/unistd.h"
        elif arch == "armhf":
            return "/usr/arm-linux-gnueabihf/include/asm/unistd.h"
        elif arch == "mips":
            return "/usr/mips-linux-gnu/include/asm/unistd.h"
        elif arch == "mips64":
            return "/usr/mips64-linux-gnuabi64/include/asm/unistd.h"
        elif arch == "powerpc64":
            return "/usr/powerpc64-linux-gnu/include/asm/unistd.h"
        elif arch == "powerpc":
            return "/usr/powerpc-linux-gnu/include/asm/unistd.h"
        elif arch == "s390x":
            return "/usr/s390x-linux-gnu/include/asm/unistd.h"
        elif arch == "sparc64":
            return "/usr/sparc64-linux-gnu/include/asm/unistd.h"
        elif arch == "x86":
            return "/usr/i686-linux-gnu/include/asm/unistd.h"
        elif arch == "x86_64":
            return "/usr/x86_64-linux-gnu/include/asm/unistd.h"
    return "/usr/include/asm/unistd.h"

def main():
    #install_debian_headers()

    if len(sys.argv) != 3:
        print("Usage: %s os arch" % sys.argv[0])
        sys.exit(1)
    os_name = sys.argv[1]
    arch_name = sys.argv[2]
    if os_name == "linux":
        errno_header = get_errno_header(os_name, arch_name)
        from mkerrno_linux import parse_errno
        errno_lines = parse_errno(errno_header)
        errno_content = "\n".join(errno_lines)
        with open("platform/{}-{}/errno.rs".format(os_name, arch_name), "w") as fh:
            fh.write(errno_content)

        unistd_header = get_sysno_header(os_name, arch_name)
        from mksysno_linux import parse_syscall
        sysno_lines = parse_syscall(unistd_header)
        sysno_content = "\n".join(sysno_lines)
        with open("platform/{}-{}/sysno.rs".format(os_name, arch_name), "w") as fh:
            fh.write(sysno_content)

if __name__ == "__main__":
    main()

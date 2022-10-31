#!/usr/bin/env python3
# Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
# Use of this source is governed by Apache-2.0 License that can be found
# in the LICENSE file.

import os
import sys

from mkcall_util import (check_system, print_call)


SUPPORTED_ARCHES = (
    "aarch64",
    "arm",
    "loongarch64",
    "mips",
    "mips64",
    "ppc64",
    "s390x",
    "x86",
    "x86_64",
)


def main():
    if not check_system("linux"):
        sys.exit(1)

    def handle_all_arch():
        template_file = "linux_call.rs"
        for arch_name in SUPPORTED_ARCHES:
            root_dir = "platform/linux-%s" % arch_name
            print_call(root_dir, template_file)

    if len(sys.argv) == 1:
        handle_all_arch()

    elif len(sys.argv) == 2:
        arch_name = sys.argv[1]
        if arch_name == "all":
            handle_all_arch()
        else:
            print_call(arch_name)
    else:
        print("Usage: %s arch-name" % sys.argv[0])
        sys.exit(1)

if __name__ == "__main__":
    main()

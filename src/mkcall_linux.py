#!/usr/bin/env python3
# Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
# Use of this source is governed by Apache-2.0 License that can be found
# in the LICENSE file.

import os
import pprint
import re
import subprocess
import sys


def parse_template():
    """Parse syscall template file.

    Returns syscall map of `{ sysno: function_body }` and template headers.
    """
    template = "linux_call.rs"
    with open(template) as fh:
        new_func_name = ""
        new_func_start = False
        headers_end = False
        headers = []
        syscalls = {}
        sysno = ""
        func_name = ""
        stack = []
        syscall_pattern = re.compile("[^S]*(SYS_\w+)")
        func_name_pattern = re.compile("pub unsafe fn ([a-z0-9_#]+)")
        for line in fh:
            if line.startswith("pub unsafe fn"):
                headers_end = True
                new_func_start = True
            if not headers_end:
                headers.append(line)
                continue

            if line:
                stack.append(line)

            if new_func_start and line == "}\n":
                for i, line in enumerate(stack):
                    if line.startswith("pub unsafe fn"):
                        m = func_name_pattern.match(line)
                        func_name = m.group(1)
                        # Remove raw identifier
                        if func_name.startswith("r#"):
                            func_name = func_name[2:]

                    elif "SYS_" in line:
                        m = syscall_pattern.match(line)
                        if m:
                            sysno = m.group(1)
                        else:
                            print("INVALID sysno:", line)
                            sys.exit(1)
                        if sysno[4:].lower() != func_name:
                            print("func name and sysno mismatch :%s:%s:" % (sysno, func_name))
                            print(line)
                            sys.exit(1)
                new_func_start = False
                if sysno not in syscalls:
                    syscalls[sysno] = list()
                syscalls[sysno].append(stack)
                stack = []
    return syscalls, headers


def read_sysnos(filepath):
    sysnos = []
    with open(filepath) as fh:
        sysno_pattern = re.compile("^pub const (SYS_\w+)")
        for line in fh:
            m = sysno_pattern.match(line)
            if m:
                sysnos.append(m.group(1))
    return sysnos


def rust_fmt(filename):
    subprocess.run(["rustfmt", filename])


def print_unimplemented_syscalls(sysnos):
    template = """
pub unsafe fn {0}() {{
    core::unimplemented!();
    // syscall0({1});
}}
"""
    for sysno in sorted(sysnos):
        call_name = sysno[4:].lower()
        print(template.format(call_name, sysno), end="")

def print_call(arch_name):
    root = "platform/linux-%s" % arch_name
    sysno_file = os.path.join(root, "sysno.rs")
    call_file = os.path.join(root, "call.rs")

    syscalls, headers = parse_template()
    sysnos = read_sysnos(sysno_file)
    matched_sysno = []
    unmatched_sysno = []

    for sysno in sysnos:
        if sysno in syscalls:
            matched_sysno.append(sysno)
        else:
            unmatched_sysno.append(sysno)
    if unmatched_sysno:
        #print("un matched sysnos:", unmatched_sysno)
        print_unimplemented_syscalls(unmatched_sysno)
        sys.exit(1)

    with open(call_file, "w") as fh:
        fh.writelines(headers)
        for sysno in sorted(matched_sysno):
            for call in syscalls[sysno]:
                fh.writelines(call)
    rust_fmt(call_file)

def main():
    def handle_all_arch():
        for arch_name in ["aarch64", "arm", "mips", "mips64","ppc64",
                          "s390x", "x86", "x86_64"]:
            print_call(arch_name)

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

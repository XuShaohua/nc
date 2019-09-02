#!/usr/bin/env python3
# Copyright (c) 2019 Xu Shaohua <xushaohua2016@outlook.com>. All rights reserved.
# Use of this source is governed by General Public License that can be found
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
        func_name_pattern = re.compile("pub fn (\w+)")
        for line in fh:
            if line.startswith("pub fn"):
                headers_end = True
                new_func_start = True

                # Remove comment of first syscall.
                if headers[-1].startswith("///"):
                    headers.pop()
            if not headers_end:
                headers.append(line)
                continue

            if line:
                stack.append(line)

            if new_func_start and line == "}\n":
                for line in stack:
                    if line.startswith("pub fn"):
                        m = func_name_pattern.match(line)
                        func_name = m.group(1)
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
                syscalls[sysno] = stack
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
pub fn {0}() {{
    core::unimplemented!();
    // syscall0({1});
}}
"""
    for sysno in sorted(sysnos):
        call_name = sysno[4:].lower()
        print(template.format(call_name, sysno), end="")

def main():
    if len(sys.argv) != 2:
        print("Usage: %s arch-name" % sys.argv[0])
        sys.exit(1)

    root = "platform/linux-%s" % sys.argv[1]
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
            fh.writelines(syscalls[sysno])
    rust_fmt(call_file)

if __name__ == "__main__":
    main()

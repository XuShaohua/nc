#!/usr/bin/env python3
# Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
# Use of this source is governed by Apache-2.0 License that can be found
# in the LICENSE file.

import os
import pprint
import re
import subprocess
import sys
import time


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
        func_name_pattern = re.compile("pub fn ([a-z0-9_#]+)")
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
                # Sometimes a function alias is critical.
                alias_line = ""
                for i, line in enumerate(stack):
                    if "Alias" in line or "Wrapper" in line:
                        alias_line = line

                    if line.startswith("pub fn"):
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

                        # SYS no. and function name not match. Nor it is a function alias.
                        if sysno[4:].lower() != func_name and not alias_line:
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
pub fn {0}() {{
    core::unimplemented!();
    // syscall0({1});
}}
"""
    for sysno in sorted(sysnos):
        call_name = sysno[4:].lower()
        print(template.format(call_name, sysno), end="")

def print_call(arch_name):
    root = "platform/freebsd-%s" % arch_name
    sysno_file = os.path.join(root, "sysno.rs")
    call_file = os.path.join(root, "call.rs")

    syscalls, headers = parse_template()
    sysnos = read_sysnos(sysno_file)
    matched_sysno = []
    unmatched_sysno = []


    last_sysno = "SYS_MUNLOCK"
    mkdir_idx = -1 
    fh = open("freebsd_call.rs", "a")
    for (idx, sysno) in enumerate(sysnos):
        if sysno == last_sysno:
            mkdir_idx = idx
            continue
        if mkdir_idx == -1:
            continue
        if sysno in syscalls:
            lines = syscalls[sysno][0]
            fh.writelines(lines)
            fh.flush()
            rust_fmt(call_file)
            commit_changelog(sysno)
            time.sleep(1)

def commit_changelog(sysno):
    func_name = sysno.replace("SYS_", "").lower()
    msg = F"freebsd: Add {func_name}()"
    subprocess.run(["python3", "mkcall_freebsd.py"])
    subprocess.run(["git", "add", "freebsd_call.rs", "platform/*"])
    subprocess.run(["git", "commit", "-m", msg])


def main():
    def handle_all_arch():
        for arch_name in ["x86_64", ]:
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

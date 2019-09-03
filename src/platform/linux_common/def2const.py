#!/usr/bin/env python3

import os
import re
import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: %s input-file" % sys.argv[0])
        sys.exit(1)

    macro_pattern = re.compile("#define\s+(\w+)\s+(\w+)(.*)\n")
    with open(sys.argv[1]) as fh:
        for line in fh:
            m = macro_pattern.match(line)
            if m:
                print("pub const {}: i32 = {};{}".format(m.group(1), m.group(2), m.group(3)))
            else:
                print(line, end="")

if __name__ == "__main__":
    main()

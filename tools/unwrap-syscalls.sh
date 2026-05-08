#!/bin/bash

# unwrap-syscall.sh
# Wraps syscallX() calls in unsafe { } blocks and formats with rustfmt

CALLS_DIR="calls"

# Check if calls directory exists
if [ ! -d "$CALLS_DIR" ]; then
    echo "Error: $CALLS_DIR directory not found"
    exit 1
fi

# Check if rustfmt is available
if ! command -v rustfmt &> /dev/null; then
    echo "Error: rustfmt is not installed"
    exit 1
fi

# Iterate over .rs files in calls/
for file in "$CALLS_DIR"/*.rs; do
    # Skip if no files match the glob
    [ -e "$file" ] || continue

    # Check if file contains syscallX() pattern
    if ! grep -qE 'syscall[0-9]+\(' "$file"; then
        echo "Skipping (no syscall pattern): $file"
        continue
    fi

    echo "Processing: $file"

    # Use perl to wrap syscallX() calls in unsafe { }
    # -0777 slurps the entire file to handle both inline and block mode calls
    # Handles two modes:
    #   Inline: syscall2(SYS___CLONE, flags, stack).map(drop) -> unsafe { syscall2(...).map(drop) }
    #   Block: multi-line syscall + method chains -> unsafe { ... } wrapping
    perl -0777 -i -pe '
        s{
            syscall(\d+)(\s*\((?:[^()]++|(?-1))*\))   # syscall with balanced parens
            ((?:\s*\.\s*\w+\s*\((?:[^()]++|(?-1))*\))*)  # method chains (same-line and multi-line)
            ([^\n;]*)                                    # same-line suffix (e.g. ` as i32`)
        }{
            my ($num, $args, $chains, $suffix) = ($1, $2, $3, $4);
            if ($args =~ /\n/ || $chains =~ /\n/) {
                # Block mode: multi-line args or multi-line chains
                "unsafe { syscall${num}${args}${chains}${suffix}\n}"
            } else {
                # Inline mode: everything on one line
                "unsafe { syscall${num}${args}${chains}${suffix} }"
            }
        }gsxe;
    ' "$file"

    # Run rustfmt to format the file
    rustfmt "$file"
done

echo "Done! Processed all .rs files in $CALLS_DIR/"

#!/usr/bin/env bash
# Filter out some spammy lines from Frama-C output

while IFS= read -r LINE
do
    # Skip file:line prefix
    MESSAGE="$(echo "$LINE" | cut -d: -f3-)"
    # Silent some warnings
    if [   "$MESSAGE" = '[kernel] Case label -1 exceeds range of unsigned int for switch expression. Nothing to worry.' \
        -o "$MESSAGE" = '[kernel] Dropping side-effect in sizeof. Nothing to worry, this is by the book.' \
        -o "$MESSAGE" = '[kernel] warning: Call to ____ilog2_NaN in constant. Ignoring this call and returning 0.' \
        -o "$MESSAGE" = '[kernel] warning: Call to __ilog2_u32 in constant. Ignoring this call and returning 0.' \
        -o "$MESSAGE" = '[kernel] warning: Call to __ilog2_u64 in constant. Ignoring this call and returning 0.' \
        -o "$MESSAGE" = '[kernel] warning: Call to __roundup_pow_of_two in constant. Ignoring this call and returning 0.' \
        -o "$MESSAGE" = '[kernel] warning: Length of array is zero. This GCC extension is unsupported. Assuming length is 1.' \
        -o "$MESSAGE" = '[kernel] warning: Unsupported packing pragma not honored by Frama-C.' ]
    then
        continue
    fi

    # Don't show false positive (non-returning functions) from include/linux/interval_tree_generic.h
    # Buggy fall-through functions would be catched by the compiler before Frama-C
    RE='^\[kernel\] warning: Body of function [a-zA-Z0-9_]*(_subtree_search|_iter_next) falls-through. Adding a return statement'
    [[ "$MESSAGE" =~ $RE ]] && continue

    # Skip a weak declaration seen after a real one
    RE='^\[kernel\] warning: def.n of func [a-zA-Z0-9_]* at .* conflicts with the one at .*; keeping the one at '
    [[ "$MESSAGE" =~ $RE ]] && continue

    # Drop a weak declaration seen first
    RE='^\[kernel\] warning: dropping duplicate def.n of func [a-zA-Z0-9_]* at .* in favor of that at '
    [[ "$MESSAGE" =~ $RE ]] && continue

    #echo "$LINE"
    echo "$MESSAGE"
done

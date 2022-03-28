#!/bin/sh
# Display the version of several software components

show_version() {
    if [ -n "$2" ]
    then
        echo "$1: $2"
    fi
}

# C
show_version gcc "$(gcc --version 2>/dev/null | head -n1)"
show_version clang "$(clang --version 2>/dev/null | head -n1)"

# C, Windows
show_version x86_64-w64-mingw32-gcc "$(x86_64-w64-mingw32-gcc --version 2>/dev/null | head -n1)"
show_version i686-w64-mingw32-gcc "$(i686-w64-mingw32-gcc --version 2>/dev/null | head -n1)"
show_version wine "$(wine --version 2>/dev/null)"

# Linux kernel and loaders
show_version 'Linux kernel' "${KERNELVER:-$(uname -r)}"
for LOADER in /lib/ld-linux.so.* ; do
    if [ -e "$LOADER" ] ; then
        show_version "$LOADER" "$("$LOADER" --version 2>/dev/null | head -n1)"
    fi
done
for LOADER in /lib/ld-musl-*.so.* ; do
    if [ -e "$LOADER" ] ; then
        show_version "$LOADER" "$("$LOADER" --version 2>&1 | head -n2 | xargs)"
    fi
done

# Python
show_version python "$(python --version 2>/dev/null)"
show_version python3 "$(python3 --version 2>/dev/null)"

# Java
show_version javac "$(javac --version 2>/dev/null)"
show_version java "$(java --version 2>/dev/null | head -n1)"

# Rust
show_version rustc "$(rustc --version 2>/dev/null)"
show_version cargo "$(cargo --version 2>/dev/null)"

# Coq
show_version coqc "$(coqc --version 2>/dev/null | xargs)"
show_version frama-c "$(frama-c --version 2>/dev/null)"

# OpenSSL
show_version openssl "$(openssl version 2>/dev/null)"

# LaTeX
show_version latexmk "$(latexmk --version 2>/dev/null | xargs)"

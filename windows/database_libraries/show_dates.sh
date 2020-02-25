#!/bin/sh
# Show libraries ordered by date
# Filter-out reproducible builds, as they do not provide a reliable timestamp

cat "$(dirname -- "$0")"/*.db/*_versions.db.json | \
    jq 'to_entries | map(.key as $k | .value.versions | map(.name_arch = $k) | .[]) | .[] | select(.debug_reproducible | not)' | \
    jq --raw-output --null-input 'reduce inputs as $in ([]; . + [$in]) | sort_by(.pe_header.timestamp) | .[] | [.pe_header.timestamp_iso, .name_arch, .string_info.FileVersion] | join(" ")' | \
    column --table

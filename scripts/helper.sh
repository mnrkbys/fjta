#!/bin/bash

to_epoch() {
  local input="$1"

  # Match input with optional fractional seconds (0 to 9 digits)
  if [[ "$input" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2})\ ([0-9]{2}:[0-9]{2}:[0-9]{2})(\.([0-9]{1,9}))?$ ]]; then
    local date_part="${BASH_REMATCH[1]}"
    local time_part="${BASH_REMATCH[2]}"
    local frac="${BASH_REMATCH[4]}"  # May be empty

    # Pad or truncate fractional part to exactly 6 digits (microseconds)
    local microsec=$(printf "%-6s" "$frac" | tr ' ' '0' | cut -c1-6)
  else
    echo "Invalid format. Expected 'yyyy-mm-dd hh:mm:ss[.f{1,9}]'" >&2
    return 1
  fi

  local formatted="$date_part $time_part"

  # Get epoch seconds in UTC
  local epoch=$(TZ=UTC date -d "$formatted" +%s)

  # Output epoch with microsecond precision
  printf "%.6f\n" "$epoch.$microsec"
}

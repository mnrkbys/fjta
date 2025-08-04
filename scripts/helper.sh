#!/bin/bash

# Convert a date string in the format 'yyyy-mm-dd hh:mm:ss[.f{1,9}]' to epoch time with microsecond precision
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


# Convert a permission string (e.g., -rwsr-sr-t) to a 4-digit octal value
perm_to_oct() {
  local permstr="$1"
  local perm=${permstr:1:9}
  local -i special=0

  digit() {
    local triplet=$1
    local pos=$2
    local -i total=0
    local -i retcode=0

    [[ "${triplet:0:1}" == "r" ]] && total+=4
    [[ "${triplet:1:1}" == "w" ]] && total+=2

    case "${triplet:2:1}" in
      x) total+=1 ;;
      s)
        total+=1
        [[ $pos -eq 0 ]] && retcode=10  # setuid
        [[ $pos -eq 1 ]] && retcode=11  # setgid
        ;;
      S)
        [[ $pos -eq 0 ]] && retcode=10  # setuid (no exec)
        [[ $pos -eq 1 ]] && retcode=11  # setgid (no exec)
        ;;
      t)
        total+=1
        [[ $pos -eq 2 ]] && retcode=12  # sticky
        ;;
      T)
        [[ $pos -eq 2 ]] && retcode=12  # sticky (no exec)
        ;;
    esac

    echo "$total"
    return $retcode
  }

  local u g o

  local u_ret
  u_ret=$(digit "${perm:0:3}" 0)
  case $? in
    10) special+=4 ;;  # setuid
  esac
  u=$u_ret

  local g_ret
  g_ret=$(digit "${perm:3:3}" 1)
  case $? in
    11) special+=2 ;;  # setgid
  esac
  g=$g_ret

  local o_ret
  o_ret=$(digit "${perm:6:3}" 2)
  case $? in
    12) special+=1 ;;  # sticky
  esac
  o=$o_ret

  echo "${special}${u}${g}${o}"
}


# Convert an octal number (base-8) to a decimal number (base-10)
oct_to_dec() {
  local octal="$1"
  echo $((8#$octal))
}


# Convert a permission string to a decimal number
perm_to_dec() {
  local permstr="$1"
  local octal=$(perm_to_oct "$permstr")
  oct_to_dec "$octal"
}

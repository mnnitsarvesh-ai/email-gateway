# Input validation helpers for the Postfix entrypoints (sourced, POSIX sh).
# Kept identical in infrastructure/postfix and infrastructure/postfix-outbound (each image is
# built from its own directory). Error messages name the variable, never its value.

die() {
  echo "postfix-entrypoint: $*; refusing to start" >&2
  exit 64
}

# require_uint NAME VALUE MIN: decimal integer >= MIN (no sign, no unit).
require_uint() {
  case "$2" in
    '' | *[!0-9]*) die "$1 must be a non-negative integer" ;;
  esac
  [ "${#2}" -le 12 ] || die "$1 is out of range"
  [ "$2" -ge "$3" ] || die "$1 must be at least $3"
}

# require_time NAME VALUE: Postfix time value (digits with an optional s/m/h/d/w unit).
require_time() {
  printf '%s' "$2" | grep -Eq '^[0-9]{1,9}[smhdw]?$' || die "$1 must be a time value such as 300s or 5d"
}

# require_enum NAME VALUE ALLOWED...: exact match against one of the allowed words.
require_enum() {
  _name=$1
  _value=$2
  shift 2
  for _allowed in "$@"; do
    [ "$_value" = "$_allowed" ] && return 0
  done
  die "$_name must be one of: $*"
}

# require_hostname NAME VALUE: DNS host name or IPv4 address (no ports, no spaces, no '$').
require_hostname() {
  printf '%s' "$2" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$' \
    || die "$1 must be a host name"
  [ "${#2}" -le 253 ] || die "$1 is too long"
}

# require_networks NAME VALUE: space/comma separated list of IPv4/IPv6 CIDRs or addresses.
require_networks() {
  [ -n "$2" ] || die "$1 must not be empty"
  for _net in $(printf '%s' "$2" | tr ',' ' '); do
    printf '%s' "$_net" | grep -Eq '^(\[?[0-9A-Fa-f:.]+\]?)(/[0-9]{1,3})?$' || die "$1 must be a list of CIDR networks"
  done
}

# require_readable NAME PATH: an existing, readable file.
require_readable() {
  case "$2" in
    /*) ;;
    *) die "$1 must be an absolute path" ;;
  esac
  [ -r "$2" ] || die "$1 does not point at a readable file"
}

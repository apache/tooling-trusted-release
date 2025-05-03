#!/bin/sh
set -eu

_url_of_urls="[URL_OF_URLS]"
_urls_prefix="[URLS_PREFIX]"

_hex_to_dec() {
  case $1 in
    0) printf 0;;
    1) printf 1;;
    2) printf 2;;
    3) printf 3;;
    4) printf 4;;
    5) printf 5;;
    6) printf 6;;
    7) printf 7;;
    8) printf 8;;
    9) printf 9;;
    a|A) printf 10;;
    b|B) printf 11;;
    c|C) printf 12;;
    d|D) printf 13;;
    e|E) printf 14;;
    f|F) printf 15;;
  esac
}

_hex2_to_oct() {
  _a="${1%"${1#?}"}"
  _b="${1#?}"
  _a_dec=$(_hex_to_dec "$_a")
  _b_dec=$(_hex_to_dec "$_b")
  _total_dec=$((_a_dec * 16 + _b_dec))
  printf "%o" "$_total_dec"
}

_url_decode() {
  _u=$1
  while [ "$_u" ]
  do
    case $_u in
      %??*)
        _hh=${_u#%}
        _hh=${_hh%"${_hh#??}"}
        case $_hh in
          [0-9A-Fa-f][0-9A-Fa-f])
            # shellcheck disable=SC2059
            printf "\\$(_hex2_to_oct "$_hh")"
            _u=${_u#%??}
            continue
        esac
        ;;
    esac
    printf %c "${_u%"${_u#?}"}"
    _u=${_u#?}
  done
}

_curl() {
  if [ -n "${CURL_EXTRA-}" ]
  then
    set -f
    # shellcheck disable=SC2086
    command curl $CURL_EXTRA "$@"
    _code=$?
    set +f
    return "$_code"
  else
    command curl "$@"
  fi
}

_curl -fsS "$_url_of_urls" | while IFS= read -r _url
do
  _rel_url_path=${_url#"$_urls_prefix"}
  [ "$_rel_url_path" = "$_url" ] && continue

  _rel_path=$(_url_decode "$_rel_url_path")
  [ -z "$_rel_path" ] && continue

  printf "Downloading %s to %s\n" "$_url" "$_rel_path"
  _curl --create-dirs -fsS "$_url" -o "$_rel_path"
done

#!/bin/sh
set -efu

_url_of_urls="[URL_OF_URLS]"

# shellcheck disable=SC2086
curl ${CURL_EXTRA:-} -fsS "$_url_of_urls" | while IFS= read -r _url_and_path
do
  _url=${_url_and_path%% *}
  _path=${_url_and_path#* }

  printf "Downloading %s\n" "$_path" || :
  # shellcheck disable=SC2086
  curl ${CURL_EXTRA:-} --create-dirs -fsS "$_url" -o "$_path"
done

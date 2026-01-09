#!/usr/bin/env bash
#
# Build and test the site content
#
# Requirement: html-proofer, jekyll
#
# Usage: See help information

set -eu

SITE_DIR="_site"

_config="_config.yml"

_baseurl=""

# By default we skip htmlproofer because this repo contains HTB / lab URLs
# and content that intentionally violates strict link rules (http, .htb, etc).
# To run htmlproofer anyway:
#   RUN_HTMLPROOFER=1 bash tools/test.sh
RUN_HTMLPROOFER="${RUN_HTMLPROOFER:-0}"

help() {
  echo "Build and test the site content"
  echo
  echo "Usage:"
  echo
  echo "   bash $0 [options]"
  echo
  echo "Options:"
  echo '     -c, --config   "<config_a[,config_b[...]]>"    Specify config file(s)'
  echo "     -h, --help               Print this information."
  echo
  echo "Environment:"
  echo "     RUN_HTMLPROOFER=1        Run htmlproofer checks (disabled by default)"
}

read_baseurl() {
  if [[ $_config == *","* ]]; then
    # multiple config
    IFS=","
    read -ra config_array <<<"$_config"

    # reverse loop the config files
    for ((i = ${#config_array[@]} - 1; i >= 0; i--)); do
      _tmp_baseurl="$(grep '^baseurl:' "${config_array[i]}" | sed "s/.*: *//;s/['\"]//g;s/#.*//")"

      if [[ -n $_tmp_baseurl ]]; then
        _baseurl="$_tmp_baseurl"
        break
      fi
    done

  else
    # single config
    _baseurl="$(grep '^baseurl:' "$_config" | sed "s/.*: *//;s/['\"]//g;s/#.*//")"
  fi
}

main() {
  # clean up
  if [[ -d $SITE_DIR ]]; then
    rm -rf "$SITE_DIR"
  fi

  read_baseurl

  # build
  JEKYLL_ENV=production bundle exec jekyll b \
    -d "$SITE_DIR$_baseurl" -c "$_config"

  # test
  if [[ "$RUN_HTMLPROOFER" == "1" ]]; then
    echo "Running htmlproofer (RUN_HTMLPROOFER=1)"
    bundle exec htmlproofer "$SITE_DIR" \
      --disable-external \
      --checks "Links,Scripts" \
      --ignore-urls "/^http:\/\/127\.0\.0\.1/,/^http:\/\/0\.0\.0\.0/,/^http:\/\/localhost/,/^http:\/\/(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/,cdn\.jsdelivr\.net/,^\/tags\//,^\/categories\//"
  else
    echo "Skipping htmlproofer (set RUN_HTMLPROOFER=1 to enable)"
  fi
}

while (($#)); do
  opt="$1"
  case $opt in
  -c | --config)
    _config="$2"
    shift
    shift
    ;;
  -h | --help)
    help
    exit 0
    ;;
  *)
    # unknown option
    help
    exit 1
    ;;
  esac
done

main


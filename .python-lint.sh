#!/bin/bash -eu

if [[ $# < 1 ]]; then
  echo >&2 "Usage: $0 [file [file ...]]"
  exit 1
fi

# Ensure isort and yapf are up-to-date
pip install -q `cat requirements-dev.txt  | grep -E 'isort|yapf'`

yapf --style '{indent_dictionary_value: True}' -i "$@"
isort -y -ns __init__.py "$@"

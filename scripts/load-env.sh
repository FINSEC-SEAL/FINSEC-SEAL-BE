#!/usr/bin/env bash
# Load .env into current shell (source this file)
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
  echo ".env loaded into environment"
else
  echo ".env not found; copy .env.template to .env and set values"
fi

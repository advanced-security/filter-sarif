#!/bin/sh
unset LD_PRELOAD
/filter-sarif \
  --input "/github/workspace/${INPUT_INPUT}" \
  --output "/github/workspace/${INPUT_OUTPUT}" \
  --split-lines \
  -- \
  "$INPUT_PATTERNS"

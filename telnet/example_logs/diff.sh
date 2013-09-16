#!/usr/bin/bash
#
# Compare two fencing logs in vim, ignoring timestamps.

vimdiff <(cut -c14- $1) <(cut -c14- $2)

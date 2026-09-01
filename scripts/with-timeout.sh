#!/bin/sh
# Run a command with a wall-clock bound, portably.
#
# GNU coreutils has timeout(1), but macOS does not ship it and Homebrew installs
# it as gtimeout, so a Makefile that depends on it protects CI and leaves
# developers unprotected -- which is backwards, since a hang costs a developer
# their afternoon and costs CI a job timeout it already has.
#
# Written for this because grype's own timeouts did not hold: it documents a 5m
# database-download bound, and a stalled refresh was observed running past
# thirty minutes (see the scan-deps target).
#
# Usage: with-timeout.sh SECONDS COMMAND [ARG...]
# Exit:  the command's status, or 124 if it was killed for exceeding SECONDS,
#        matching GNU timeout(1) so callers can tell the two apart.

set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 SECONDS COMMAND [ARG...]" >&2
    exit 2
fi

seconds="$1"
shift

case "$seconds" in
    ''|*[!0-9]*)
        echo "$0: SECONDS must be a whole number, got '$seconds'" >&2
        exit 2
        ;;
esac

"$@" &
command_pid=$!

# The watchdog kills the command if it outlives the bound. TERM first so the
# command can clean up; KILL after a grace period in case it ignores TERM.
(
    sleep "$seconds"
    kill -TERM "$command_pid" 2>/dev/null || exit 0
    sleep 5
    kill -KILL "$command_pid" 2>/dev/null || true
) &
watchdog_pid=$!

# `wait` reports the command's status, or its signal, whichever comes first.
# stderr is redirected only around the wait: when the watchdog kills the
# command, the shell announces "Terminated: 15" here, which reads as an error in
# a CI log when it is this script working correctly. The command's own stderr
# was never routed through this line.
status=0
{ wait "$command_pid"; } 2>/dev/null || status=$?

# The watchdog has done its job either way; stop it before it fires late.
kill -TERM "$watchdog_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true

# A shell reports a signalled child as 128+signal. SIGTERM is 15 and SIGKILL is
# 9, so these are the watchdog's work rather than the command's own failure.
if [ "$status" -eq 143 ] || [ "$status" -eq 137 ]; then
    echo "$0: '$1' exceeded ${seconds}s and was killed" >&2
    exit 124
fi

exit "$status"

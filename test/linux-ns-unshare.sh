#!/bin/sh

# Meaningful tests require the freedom to break things.  Linux namespaces can
# give us a disposable sandbox without the need for persistent changes and
# end-user configuration.  If the host allows unprivileged userns, tests can even
# run without root.

if [ -z "$AM_BUILDDIR" ]
then
	echo "1..0 # Skipped: missing \$AM_BUILDDIR"
	echo "# Did you run me under 'make check'?"
	exit
fi

if ! ((unshare --help | grep map-root-user) && ip link show) > /dev/null
then
	echo "1..0 # Skipped: required linux utilities seem to be missing"
	echo "# Test requires util-linux >= 2.25 and iproute2"
	exit
fi

if ! unshare --user --map-root-user --net true
then
	echo "1..0 # Skipped: unable to create private user/network namespace"
	echo "# Test requires root or kernel.unprivileged_userns_clone=1"
	exit
fi

export LC_CTYPE=C

STAGE1_NETNS=$(readlink /proc/$$/ns/net | grep -E '^net:\[[0-9]+\]$')
export STAGE1_NETNS

STAGE2="$AM_SRCDIR/test/linux-ns-unshare-stage2.sh"

if ! unshare --user --map-root-user --net "$AM_SHELL" "$STAGE2"
then
	echo "Bail out! Failure in second stage"
	exit
fi

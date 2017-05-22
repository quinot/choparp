#!/bin/sh

#
# Verify the sandbox created in stage1 and proceed with functional tests.
#

STAGE2_NETNS=$(readlink /proc/$$/ns/net | grep -E '^net:\[[0-9]+\]')

if [ -z "$STAGE1_NETNS" ] || -z [ "$STAGE2_NETNS" ] ||
	[ "$STAGE1_NETNS" '=' "$STAGE2_NETNS" ]
then
	echo "Bail out! Failed to confirm sandbox"
	exit
fi

. "$AM_SRCDIR/test/linux-veth.sh"

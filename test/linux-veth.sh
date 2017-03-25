#!/bin/sh

if [ "x$choparp_abspath" = x ]
then
	echo "1..0 # Skipped: missing \$choparp_abspath (did you run me as 'make check'?) "
	exit
fi

CHOPARP_NETNS="$(ls -ld /proc/$$/ns/net)"
CHOPARP_NETNS="${CHOPARP_NETNS#*->}"
STAGE="${1-stage1}"

if [ "${TAP_RUNNER_NETNS+set}" != "set" ] && [ "$STAGE" = "stage1" ]
then
	export LC_CTYPE=C
	export TAP_RUNNER_NETNS="$CHOPARP_NETNS"
	# stash and restore stdout, pass pipeline as file descriptor 5
	exec 4>&1
	STAGE2_STATUS=$(unshare --user --map-root-user --net "$sh_test_shell" "$0" stage2 5>&1 1>&4)
	if [ "$STAGE2_STATUS" != "STAGE2_REACHED" ]
	then
		echo "1..0 # Skipped: unable to create private user/network namespace (need root?)"
	fi
	exit
fi
if [ "$TAP_RUNNER_NETNS" = "$CHOPARP_NETNS" ]
then
	# sanity check, should never occur
	exit 1
fi

echo "1..9"
echo STAGE2_REACHED >&5

rnd_byte="$(dd if=/dev/urandom bs=1 count=1 2>/dev/null | od -A n -t d)"

lladdr() {
	printf '02:00:c0:a8:%02x:%02x' "$rnd_byte" "$1"
}

ipaddr() {
	printf '192.168.%d.%d' "$rnd_byte" "$1"
}

hex_ipaddr() {
	printf '0xc0a8%02x%02x' "$rnd_byte" "$1"
}

arp_for() {
	(
		for i
		do
			ping -I who-has -c 1 -w 1 $(ipaddr $i) &
		done
		wait # for all jobs in this subshell
	) > /dev/null
}

found() {
	ip -4 neigh show dev who-has | \
		grep -i -q "$(ipaddr $1) lladdr ${2:-.*} REACHABLE"
}

set -x

ip link add is-at type veth peer name who-has
ip addr add 192.168.1.200/24 dev who-has
ip link set is-at up
ip link set who-has up

#######################################################################

test_desc="1 - Base case, static hardware address and single-host"
"$choparp_abspath" is-at $(lladdr 1) $(ipaddr 1) &
chopid=$!
sleep 1

arp_for 1
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! found 1
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="2 - Target IP by legacy subnet"
"$choparp_abspath" is-at $(lladdr 2) $(ipaddr 2)/255.255.255.254 &
chopid=$!
sleep 1

arp_for 2 3
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! (found 2 && found 3)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="3 - Target IP by BSD-style hex"
"$choparp_abspath" is-at $(lladdr 4) $(hex_ipaddr 4)/0xfffffffe &
chopid=$!
sleep 1

arp_for 4
arp_for 5
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! (found 4 && found 5)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="4 - Target IP by IP list"
"$choparp_abspath" is-at $(lladdr 6) $(ipaddr 6) $(ipaddr 7) &
chopid=$!
sleep 1

arp_for 6 7
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! (found 6 && found 7)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="5 - Target IP by CIDR subnet and exclusion"
"$choparp_abspath" is-at $(lladdr 8) $(ipaddr 8)/30 -$(ipaddr 10) &
chopid=$!
sleep 1

arp_for 8 9 10 11
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! (found 8 && found 9 && ! found 10 && found 11)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="6 - Hardware address detection by \"auto\" keyword"
"$choparp_abspath" is-at auto $(ipaddr 12) &
chopid=$!
sleep 1

arp_for 12
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! found 12
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="7 - Hardware address by \"vhid\" keyword, decimal"
"$choparp_abspath" is-at vhid:13 $(ipaddr 13) &
chopid=$!
sleep 1

arp_for 13
kill $chopid

ip neigh show dev who-has

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! found 13 00:00:5e:00:01:0d
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="8 - Hardware address by \"vhid\" keyword, hex"
"$choparp_abspath" is-at vhid:0x0e $(ipaddr 14) &
chopid=$!
sleep 1

arp_for 14
kill $chopid

ip neigh show dev who-has

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! found 14 00:00:5e:00:01:0e
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="9 - Pidfile with -p"
pidfile=$(mktemp /tmp/choparp.pid-XXXXXXXX)
"$choparp_abspath" -p $pidfile is-at auto $(ipaddr 15) &
chopid=$!
sleep 1

chopid_from_file=$(cat $pidfile)
arp_for 15
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit"
elif ! found 15
then
	echo "not ok $test_desc # MAC resolution failure"
elif [ "$chopid" -ne "$chopid_from_file" ]
then
	echo "not ok $test_desc # invalid pidfile"
elif [ -f "$pidfile" ]
then
	echo "not ok $test_desc # pidfile not removed after exit"
else
	echo "ok $test_desc"
fi

#######################################################################

# Cleanup
ip link delete is-at

exit 0

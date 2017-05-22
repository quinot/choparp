#!/bin/sh

#
# Functional tests. Do NOT run this on a production system or any environment
# not devoted to testing. This script is normally run from linux-ns-unshare.sh
# which configures a sandbox. Docker, GitLab, autopkgtest, etc are fine too.
# Just don't run this script casually.
#

set -x

if [ -z "$AM_BUILDDIR" ]
then
	echo "1..0 # Skipped: missing \$AM_BUILDDIR"
	echo "# Did you run me under 'make check'? "
	exit
fi

if ! ip link add is-at type veth peer name who-has ||
	! ip addr add 192.168.1.200/24 dev who-has     ||
	! ip link set is-at up                         ||
	! ip link set who-has up
then
	echo "1..0 # Skipped: unable to set up private veth interfaces"
	exit
fi

# Allow this many seconds for choparp start-up before sending test arp requests
startup_grace=1

# Any arbitrary value should do, but might as well switch it up between runs
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

#######################################################################

echo "1..9"

#######################################################################

test_desc="1 - Base case, static hardware address and single-host"
"$AM_BUILDDIR"/choparp is-at $(lladdr 1) $(ipaddr 1) &
chopid=$!
sleep $startup_grace

arp_for 1
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 1
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="2 - Target IP by legacy subnet"
"$AM_BUILDDIR"/choparp is-at $(lladdr 2) $(ipaddr 2)/255.255.255.254 &
chopid=$!
sleep $startup_grace

arp_for 2 3
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! (found 2 && found 3)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="3 - Target IP by BSD-style hex"
"$AM_BUILDDIR"/choparp is-at $(lladdr 4) $(hex_ipaddr 4)/0xfffffffe &
chopid=$!
sleep $startup_grace

arp_for 4
arp_for 5
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! (found 4 && found 5)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="4 - Target IP by IP list"
"$AM_BUILDDIR"/choparp is-at $(lladdr 6) $(ipaddr 6) $(ipaddr 7) &
chopid=$!
sleep $startup_grace

arp_for 6 7
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! (found 6 && found 7)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="5 - Target IP by CIDR subnet and exclusion"
"$AM_BUILDDIR"/choparp is-at $(lladdr 8) $(ipaddr 8)/30 -$(ipaddr 10) &
chopid=$!
sleep $startup_grace

arp_for 8 9 10 11
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! (found 8 && found 9 && ! found 10 && found 11)
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="6 - Hardware address detection by \"auto\" keyword"
"$AM_BUILDDIR"/choparp is-at auto $(ipaddr 12) &
chopid=$!
sleep $startup_grace

arp_for 12
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 12
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="7 - Hardware address by \"vhid\" keyword, decimal"
"$AM_BUILDDIR"/choparp is-at vhid:13 $(ipaddr 13) &
chopid=$!
sleep $startup_grace

arp_for 13
kill $chopid

ip neigh show dev who-has

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 13 00:00:5e:00:01:0d
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="8 - Hardware address by \"vhid\" keyword, hex"
"$AM_BUILDDIR"/choparp is-at vhid:0x0e $(ipaddr 14) &
chopid=$!
sleep $startup_grace

arp_for 14
kill $chopid

ip neigh show dev who-has

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 14 00:00:5e:00:01:0e
then
	echo "not ok $test_desc # MAC resolution failure"
else
	echo "ok $test_desc"
fi

#######################################################################

test_desc="9 - Pidfile with -p"
pidfile=$(mktemp /tmp/choparp.pid-XXXXXXXX)
"$AM_BUILDDIR"/choparp -p $pidfile is-at auto $(ipaddr 15) &
chopid=$!
sleep $startup_grace

chopid_from_file=$(cat "$pidfile")
arp_for 15
kill $chopid

if ! wait $chopid
then
	echo "not ok $test_desc # abnormal exit $?"
elif ! found 15
then
	echo "not ok $test_desc # MAC resolution failure"
elif ! [ "$chopid" -eq "$chopid_from_file" ]
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

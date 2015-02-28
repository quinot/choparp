choparp
=======

  * Copyright (c) 1997 Takamichi Tateoka (tree@mma.club.uec.ac.jp)
  * Copyright (c) 2002-2015 Thomas Quinot (thomas@cuivre.fr.eu.org)

Changes and original English man page from the FreeBSD port by
Jun-ichiro itojun Hagino <itojun@freebsd.org>.

Changes from the NetBSD package by Darrin B. Jewell <dbj@netbsd.org>.

Introduction
------------

choparp is a proxy ARP daemon. It listens for ARP requests on a
network interface, and sends ARP replies with a specified MAC
addresses when the requested IP addresses matches a user-provided
list.

Build instructions
------------------

Requires libpcap.

`gcc -o choparp choparp.c -lpcap`

Usage example
-------------

For example, assume following VLSM subnet.  R1 and H1 must have
routing entry for subnet B (172.21.139.32/28).

```
  +----+                            +----+
  | R1 |                            | H1 |
  +-+--+                            +----+
    | 172.21.139.1                    | 172.21.139.96
    |                                 |
  --+--------+------------------------+--------------- subnet A
             |                                   172.21.139.0/24
             | 172.21.139.2
           +----+
           | R2 |
           +----+
             | 172.21.139.33
             |
       ------+-----------------+---------------------- subnet B
                               |                 172.21.139.32/28
                               | 172.21.139.33
                             +----+
                             | H2 |
                             +----+
```

If you can not set such routing entry, R1 and H1 treat hosts on the
subnet B as on the subnet A.  In this case, H1 broadcast ARP request
for H2 to send a message for H2.  This request will fail since this
request can not reach to subnet B (and H2), thus H1 cannot tail with
H2.

choparp running on R2 replies for ARP request, which is looking for
MAC address of H2, as R2 is H2 on subnet A.  Hosts on subnet A send
packets for H2 to R2 (because R2 replies H2 is R2), and R2 can forward
the packets to R2 with ordinary way.  As a result, H1 and H2 can talk
each other.  You can *chop* subnet B from subnet A without any routing
modification on subnet A.

This is a same way as proxy ARP described in RFC1027.

For above example, you should run choparp on R2, set if_name parameter
as the interface on 172.21.139.2, network parameter as
172.21.139.32/255.255.255.240 (or 172.21.139.32/28).  You should not
use 172.21.139.32 and 172.21.139.47 as IP address for hosts because
they are used as network address and broadcast address for subnet B.

Enjoy!


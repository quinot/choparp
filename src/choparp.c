/*
   choparp - cheap & omitted proxy arp

   Copyright (c) 1997 Takamichi Tateoka (tree@mma.club.uec.ac.jp)
   Copyright (c) 2002-2015 Thomas Quinot (thomas@cuivre.fr.eu.org)
   
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the authors nor the names of their contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.
   
   THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   SUCH DAMAGE.


   History:
   17 Jun 1997	Creation (tate)
   7  Oct 1997	fix some comments (tate)
   19 Jun 1998  fix read result as ssize_t (tate / pointed by msaitoh)

*/

#define _GNU_SOURCE /* asprintf */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifndef __linux__
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif

/* ARP Header                                      */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 

struct cidr {
	struct cidr *next;
	struct in_addr addr;		/* addr and mask are host order */
	struct in_addr mask;
};

struct cidr *targets = NULL, *excludes = NULL;
char errbuf[PCAP_ERRBUF_SIZE];
u_char target_mac[ETHER_ADDR_LEN];	/* target MAC address */

char* cidr_to_str(struct cidr *a) {
    char buf[64];
    char *res = NULL;
    int res_alloc, res_len;
    int len;

    while (a) {
        if (a->mask.s_addr == INADDR_NONE) {
            len = snprintf(buf, sizeof buf, "dst host %s", inet_ntoa(a->addr));
        } else {
            len = snprintf(buf, sizeof buf, "dst net %s mask ", inet_ntoa(a->addr));
            len += snprintf(buf + len, sizeof buf - len, "%s", inet_ntoa(a->mask));
        }

        if (!res) {
            res_alloc = 1024;
            res = malloc(res_alloc);
            strncpy(res, buf, res_alloc);
            res_len = len;

        } else {
            if (res_len + len + 5 > res_alloc) {
                res_alloc *= 2;
                res = realloc(res, res_alloc);
            }
            strncat(res, " or ", res_alloc - res_len - 1);
            res_len += 4;
            strncat(res, buf, res_alloc - res_len - 1);
            res_len += len;
        }

        a = a->next;
    }
    return res;
}

pcap_t *
open_pcap(char *ifname, char *filter_str) {
    pcap_t *pc = NULL;
    struct bpf_program filter;

    /* Set up PCAP */
    if ((pc = pcap_open_live(ifname, 128, 0,  512, errbuf))==NULL){
       fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
       exit(1);
    }
    
    /* Compiles the filter expression */ 
    if (pcap_compile(pc, &filter, filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1){
       fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pc) );
       exit(1);
    }

    /* Set filter program */ 
    if (pcap_setfilter(pc, &filter) == -1){
       fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pc));
       exit(1);
    }

    pcap_freecode(&filter);
    return pc;
}

void
gen_arpreply(u_char *buf) {
    struct ether_arp *arp;
    struct in_addr ipbuf;

    /* set ethernet dst/src address */
    memcpy(buf, buf+ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    memcpy(buf+ETHER_ADDR_LEN, target_mac, ETHER_ADDR_LEN);

    /* set result of ARP request */
    arp = (struct ether_arp *)(buf + ETHER_HDR_LEN);
    memcpy((char*) &ipbuf, arp->arp_tpa, sizeof(ipbuf));	/* save protocol addr */
    memcpy(arp->arp_tha, arp->arp_sha, sizeof(arp->arp_tha)); /* set target hard addr */
    memcpy(arp->arp_tpa, arp->arp_spa, sizeof(arp->arp_tpa)); /* set target proto addr */
    memcpy(arp->arp_spa, (char *)&ipbuf, sizeof(ipbuf));	              /* set source protocol addr */
    memcpy(arp->arp_sha, target_mac, ETHER_ADDR_LEN);         /* set source hard addr */
    arp->arp_op = htons(ARPOP_REPLY);
}

void
process_arp(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    gen_arpreply((u_char *)packet);
    pcap_inject((pcap_t *)user, packet, pkthdr->len);
}

int
setmac(char *addr, char *ifname){
    u_int m0, m1, m2, m3, m4, m5;

    if (!strcmp (addr, "auto")) {
#ifdef __linux__
        int fd;
        struct ifreq ifr;

        if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket");
            return -1;
        }

        strncpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl(SIOCGIFHWADDR)");
            return -1;
        }
        memcpy(target_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
        return 0;
#else
        struct ifaddrs *ifas, *ifa;

        getifaddrs (&ifas);
        for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
#define SDL ((struct sockaddr_dl *)ifa->ifa_addr)
            if (strcmp (ifa->ifa_name, ifname)
              || SDL->sdl_family != AF_LINK
              || SDL->sdl_alen != ETHER_ADDR_LEN)
                continue;
            memcpy (target_mac, SDL->sdl_data + SDL->sdl_nlen, ETHER_ADDR_LEN);
            return 0;
        }
#endif
        fprintf(stderr, "%s: not found\n", ifname);
        return -1;

    } else if (!strncmp (addr, "vhid:", 4)) {
        /*
         * Virtual router mac address
         * CARP address format: 00:00:5e:00:01:<VHID>
         */
        char *vhid = addr + 5;
        if (!*vhid)
            return(-1);
        m0 = 0;
        m1 = 0;
        m2 = 0x5e;
        m3 = 0;
        m4 = 1;
        m5 = atoi(vhid);
    } else if (sscanf(addr, "%x:%x:%x:%x:%x:%x", &m0, &m1, &m2, &m3, &m4, &m5) < 6) {
        fprintf(stderr, "invalid MAC address: %s", addr);
        return(-1);
    }
    target_mac[0] = (u_char )m0;
    target_mac[1] = (u_char )m1;
    target_mac[2] = (u_char )m2;
    target_mac[3] = (u_char )m3;
    target_mac[4] = (u_char )m4;
    target_mac[5] = (u_char )m5;
    return(0);
}

int
atoip(char *buf, u_int32_t *ip_addr){
    u_int	i0, i1, i2, i3;

    if (sscanf(buf, "%u.%u.%u.%u", &i0, &i1, &i2, &i3) == 4){
	*ip_addr = (i0 << 24) + (i1 << 16) + (i2 << 8) + i3;
	return(0);
    }
    if (sscanf(buf, "0x%lx", (unsigned long *) ip_addr) == 1)
	return(0);

    return(-1);	
}

void
usage(void){
    fprintf(stderr,"usage: choparp if_name mac_addr [-]addr/mask...\n");
    exit(-1);
}

int
main(int argc, char **argv){
    pcap_t *pc;
    char *ifname;
    char *filter, *targets_filter, *excludes_filter;
    struct cidr **targets_tail = &targets, **excludes_tail = &excludes;
#define APPEND(LIST,ADDR,MASK) \
    do {							\
	*(LIST ## _tail) = malloc(sizeof (struct cidr));	\
	(*(LIST ## _tail))->addr.s_addr = htonl(ADDR);		\
	(*(LIST ## _tail))->mask.s_addr = htonl(MASK);		\
	(*(LIST ## _tail))->next = NULL;			\
	(LIST ## _tail) = &(*(LIST ## _tail))->next;		\
    } while (0)

    if (argc < 4)
	usage();

    ifname = argv[1];
    if (setmac(argv[2], ifname)) {
        exit(1);
    }
    argv += 3; argc -= 3;

    while (argc > 0) {
	u_int32_t addr, mask = ~0;
        char *slash = strchr (*argv, '/');
	int exclude = 0;

	if (**argv == '-') {
	    (*argv)++;
	    exclude = 1;
	}
	if (slash != NULL)
	    *(slash++) = '\0';
	if (atoip (*argv, &addr))
	    usage();
	if (slash != NULL) {
	    char *end;
	    u_int32_t len = strtol (slash, &end, 10);
	    if (*end == '\0')
		mask <<= (32 - len);
	    else if (atoip (slash, &mask))
		usage();
	}
	if (exclude)
	    APPEND(excludes, addr, mask);
	else
	    APPEND(targets, addr, mask);

	argv++, argc--;
    }

#ifdef DEBUG
#define SHOW(LIST) \
    do {							\
	struct cidr *t;						\
	fprintf (stderr, #LIST ":\n");				\
	for (t = LIST; t; t = t->next) {			\
	    fprintf (stderr, "  %s", inet_ntoa (t->addr));	\
	    fprintf (stderr, "/%s\n", inet_ntoa (t->mask));	\
	}							\
    } while (0)

    SHOW(targets);
    SHOW(excludes);
    exit (0);
#endif

    targets_filter = cidr_to_str(targets);
    excludes_filter = cidr_to_str(excludes);

#define TMPL_FILTER "arp[2:2] == 0x0800 " /* Protocol: IPv4 */       \
                    "and arp[4] == 6 "    /* Hw addr length: 6 */    \
                    "and arp[5] == 4 "    /* Proto addr length: 4 */ \
                    "and arp[6:2] == 1 "  /* Operation: Request */   \
                    "and (%s)"

#define EXCL_FILTER TMPL_FILTER " and not (%s)"
    if (excludes_filter == NULL)
        asprintf (&filter, TMPL_FILTER, targets_filter);
    else
        asprintf (&filter, EXCL_FILTER, targets_filter, excludes_filter);

#ifdef DEBUG
        fprintf(stderr, "Filter on %s: %s\n", ifname, filter);
#endif
    if ((pc = open_pcap(ifname, filter)) < 0)
	exit(1);
    free(filter);
    pcap_loop(pc, 0, process_arp, (u_char*)pc);
    exit(1);
}

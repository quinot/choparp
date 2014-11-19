/*
   choparp - cheap & omitted proxy arp

   Copyright (c) 1997 Takamichi Tateoka (tree@mma.club.uec.ac.jp)
   Copyright (c) 2002 Thomas Quinot (thomas@cuivre.fr.eu.org)
   
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
/* #include <net/if_arp.h> */
#if (__FreeBSD__ >= 3)
 #include <net/if_var.h>
#endif
#include <netinet/if_ether.h>
#include <sys/param.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if_dl.h>

#ifdef DEBUG
#include <arpa/inet.h>
#endif

#define	BPFFILENAME	"/dev/bpf%d"	/* bpf file template */
#ifndef	NBPFILTER			/* number of available bpf */
# define NBPFILTER (16)
#endif

struct cidr {
	struct cidr *next;
	u_int32_t addr;		/* addr and mask are host order */
	u_int32_t mask;
};

struct cidr *targets = NULL, *excludes = NULL;
u_char	target_mac[ETHER_ADDR_LEN];	/* target MAC address */

/*
   ARP filter program
*/
struct bpf_insn bpf_filter_arp[] = {
    /* check Ethernet Encapsulation (RFC894) first */
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),	/* load frame type */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP, 0, 3), /* check it */
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20),	/* load OP code */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARPOP_REQUEST, 0, 1),  /* check it */
    BPF_STMT(BPF_RET+BPF_K, 14+28),	/* return Ethernet encap ARP req. */
    /* XXX: IEEE 802.2/802.3 Encap (RFC1042) should be available... */
    BPF_STMT(BPF_RET+BPF_K, 0),		/* discard */
};

/*
   openbpf:

   open bpf & set ARP filter program for named interface &
   allocate enough buffer for BPF.
   return file descripter or -1 for error
*/
int
openbpf(char *ifname, char **bufp, size_t *buflen){
    char bpffile[sizeof(BPFFILENAME)+5];	/* XXX: */
    int	fd = -1;
    int	n;
    struct bpf_version	bpf_version;
    struct ifreq	bpf_ifreq;
    u_int	ui;
    struct bpf_program	bpf_program;

    /* open BPF file */
    for (n=0; n<NBPFILTER; n++){
	snprintf(bpffile, sizeof(bpffile), BPFFILENAME, n);
	if ((fd = open(bpffile, O_RDWR, 0)) >= 0)
	    break;
    }
    if (fd < 0){
	fprintf(stderr,"openbpf: Can't open BPF\n");
	return(-1);		/* error */
    }

    /* check version number */
    if ((ioctl(fd, BIOCVERSION, &bpf_version) == -1) ||
	bpf_version.bv_major != BPF_MAJOR_VERSION ||
	bpf_version.bv_minor < BPF_MINOR_VERSION){
	fprintf(stderr,"openbpf: incorrect BPF version\n");
	close(fd);
	return(-1);
    }

    /* set interface name */
    strncpy(bpf_ifreq.ifr_name, ifname, IFNAMSIZ);
    bpf_ifreq.ifr_name[IFNAMSIZ-1] = '\0';	/* paranoia */
    if (ioctl(fd, BIOCSETIF, &bpf_ifreq) == -1){
	fprintf(stderr,"openbpf: BIOCSETIF failed for interface <%s>\n",
		ifname);
	close(fd);
	return(-1);
    }

    /* set BPF immediate mode */
    ui = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &ui) == -1){
	fprintf(stderr,"openbpf: BIOCIMMEDIATE failed.\n");
	close(fd);
	return(-1);
    }

    /* set ARP request filter */
    bpf_program.bf_len = sizeof(bpf_filter_arp) / sizeof(struct bpf_insn);
    bpf_program.bf_insns = bpf_filter_arp;
    if (ioctl(fd, BIOCSETF, &bpf_program) == -1){
	fprintf(stderr,"openbpf: BIOCSETF failed.\n");
	close(fd);
	return(-1);
    }

    /* allocate reasonable size & alimented buffer */
    if (ioctl(fd, BIOCGBLEN, &ui) == -1){
	fprintf(stderr,"openbpf: BIOCGBLEN failed.\n");
	close(fd);
	return(-1);
    }
    *buflen = (size_t)ui;
    if ((*bufp = (char *)malloc((size_t) ui)) == NULL){
	fprintf(stderr,"openbpf: malloc failed.\n");
	close(fd);
	return(-1);
    }

    return(fd);
}

/*
   get ARP datalink frame pointer

   NULL if no more ARP frame
*/
char *
getarp(char *bpfframe, ssize_t bpfflen, char **next, ssize_t *nextlen){
    int	bias;
    char *p;

    if (bpfframe == NULL || bpfflen == 0)
	return(NULL);

    bias = BPF_WORDALIGN(((struct bpf_hdr *)bpfframe)->bh_hdrlen +
			 ((struct bpf_hdr *)bpfframe)->bh_caplen);
    if (bias < bpfflen){
	/* there is another packet packed into same bpf frame */
	*next = bpfframe + bias;
	*nextlen = (size_t) bpfflen - bias;
    } else {
	/* no more packet */
	*next = NULL;
	*nextlen = 0;
    }

    /* cut off BPF header */
    p = bpfframe + ((struct bpf_hdr *)bpfframe)->bh_hdrlen;
    return(p);
}

/*
   match

   match an IP address against a list of address/netmask pairs
*/

static int
match (u_int32_t addr, struct cidr *list) {
    while (list) {
	if ((addr & list->mask) == list->addr)
	    return 1;
	list = list->next;
    }
    return 0;
}

/*
   checkarp

   check responsibility of the ARP request
   return true if responsible

   arpbuf is pointing top of link-level frame
*/

static int
checkarp(char *arpbuf){
    struct ether_arp	*arp;
    u_int32_t	target_ip;

    arp = (struct ether_arp *)(arpbuf + 14);	/* skip ethernet header */
    if (ntohs(arp->arp_hrd) != ARPHRD_ETHER ||
	/* XXX: ARPHRD_802 */
	ntohs(arp->arp_pro) != ETHERTYPE_IP ||
	(int) (arp->arp_hln) != ETHER_ADDR_LEN || /* length of ethernet addr */
	(int) (arp->arp_pln) != 4){  /* length of protocol addr */
	fprintf(stderr,"checkarp: WARNING: received unknown type ARP request.\n");
	return(0);
    }
    target_ip = ntohl(*(u_int32_t *)(arp->arp_tpa));
    return match(target_ip, targets) && !match(target_ip, excludes);
}

/*
   genarpreply

   generate arp reply link level frame
   arpbuf is pointing top of link-level frame
   this routine overwrite arpbuf

   return reply buffer & its length
*/
char *
gen_arpreply(char *arpbuf, size_t *rlen){
    struct ether_arp	*arp;
    u_char	ipbuf[4];	/* sender IP */

    /* set ethernet dst/src address */
    memcpy(arpbuf, arpbuf+ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    memcpy(arpbuf+ETHER_ADDR_LEN, target_mac, ETHER_ADDR_LEN);
    /* set result of ARP request */
    arp = (struct ether_arp *)(arpbuf + 14);	/* skip ethernet header */
    memcpy(ipbuf, arp->arp_tpa, 4);		/* save protocol addr */
    memcpy(arp->arp_tha, arp->arp_sha, 10); /* set target hard/proto addr */
    memcpy(arp->arp_spa, ipbuf, 4);		/* set source protocol addr */
    memcpy(arp->arp_sha, target_mac, ETHER_ADDR_LEN); /* set source hard addr */
    arp->arp_op = htons(ARPOP_REPLY);

    *rlen = 14 + 28;		/* ethernet header & arp reply */
    return(arpbuf);
}

void
loop(int fd, char *buf, size_t buflen){
    ssize_t  rlen;
    char    *p, *nextp;
    ssize_t  nextlen;
    char    *rframe;
    char    *sframe;
    size_t  frame_len;
    fd_set  fdset;

    FD_ZERO(&fdset);
    FD_SET(fd,&fdset);

    for(;;){
        int r = select(fd+1,&fdset, 0, 0, 0);

        if (r < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            return;
        }

        rlen = read(fd, buf, buflen);
        if (rlen < 0) {
            if (errno == EINTR)
                continue;
            perror("read");
            return;
        }

	p = buf;
	while((rframe = getarp(p, rlen, &nextp, &nextlen)) != NULL){
	    if (checkarp(rframe)){
		sframe = gen_arpreply(rframe, &frame_len);
		write(fd, sframe, frame_len);
	    }
	    p = nextp;
	    rlen = nextlen;
	}
    }
    /* not reach */
}

int
setmac(char *addr, char *ifname){
    u_int m0, m1, m2, m3, m4, m5;

    if (!strcmp (addr, "auto")) {
	struct ifaddrs *ifas, *ifa;

	getifaddrs (&ifas);
	for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
#define SDL ((struct sockaddr_dl *)ifa->ifa_addr)
	    if (strcmp (ifa->ifa_name, ifname)
	      || SDL->sdl_family != AF_LINK
	      || SDL->sdl_alen != 6)
		continue;
	    memcpy (target_mac, SDL->sdl_data + SDL->sdl_nlen, 6);
	    return 0;
	}
	return -1;
    } else if (!strncmp (addr, "vhid", 4)) {
        // virtual router mac address
        // CARP address format: 00:00:0e:00:01:<HEX_VHID>
        char *vhid = addr + 4;
        if (!*vhid)
            return(-1);
        m0 = 0;
        m1 = 0;
        m2 = 0x5e;
        m3 = 0;
        m4 = 1;
        m5 = atoi(vhid);
    }
    if (sscanf(addr, "%x:%x:%x:%x:%x:%x", &m0, &m1, &m2, &m3, &m4, &m5) < 6)
        return(-1);
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
    int	fd;
    char *buf, *ifname;
    struct cidr **targets_tail = &targets, **excludes_tail = &excludes;
#define APPEND(LIST,ADDR,MASK) \
    do {							\
	*(LIST ## _tail) = malloc(sizeof (struct cidr));	\
	(*(LIST ## _tail))->addr = ADDR;			\
	(*(LIST ## _tail))->mask = MASK;			\
	(*(LIST ## _tail))->next = NULL;			\
	(LIST ## _tail) = &(*(LIST ## _tail))->next;		\
    } while (0)
    size_t buflen;

    if (argc < 4)
	usage();

    ifname = argv[1];
    if (setmac(argv[2], ifname))
	usage();
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
    do {								\
	struct cidr *t;							\
	printf (#LIST ":\n");						\
	for (t = LIST; t; t = t->next) {				\
	    u_int32_t x;							\
	    x = htonl (t->addr);					\
	    printf ("  %s", inet_ntoa (*(struct in_addr *)&x));		\
	    x = htonl (t->mask);					\
	    printf ("/%s\n", inet_ntoa (*(struct in_addr *)&x));	\
	}								\
    } while (0)

    SHOW(targets);
    SHOW(excludes);
    exit (0);
#endif
    if ((fd = openbpf(ifname, &buf, &buflen)) < 0)
	return(-1);
    loop(fd, buf, buflen);
    return(-1);
}

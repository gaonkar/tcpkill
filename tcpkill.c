/*
 * tcpkill.c
 *
 * Kill TCP connections already in progress.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: tcpkill.c,v 1.17 2001/03/17 08:10:43 dugsong Exp $
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>
#include <assert.h>

#include "pcaputil.h"
#include "version.h"

#define DEFAULT_SEVERITY	3
#define SEC(_x) ((_x) * 1000000)

int	Opt_severity = DEFAULT_SEVERITY;
int	pcap_off;
pcap_t  *pd;
int     Opt_max_kill = 0;
int     kill_counter = 0;

struct ConnectionPair {
    unsigned long src_ip;
    unsigned long dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
};

struct ConnectionPair mypair={0};

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: tcpkill [-i interface] [-m max kills] [-r num_rst_packets] \n"
		"\t-s\tsource ip address\n"
		"\t-d\tdestination ip address\n"
		"\t-p\tsource port\n"
		"\t-q\tdestination port\n");
}

static void
tcp_kill_cb(u_char *user, const struct pcap_pkthdr *pcap, const u_char *pkt)
{
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	char ctext[64];
	u_int32_t seq, win, ack;
	int i;
	libnet_t *l;

	l = (libnet_t *)user;
	pkt += pcap_off;
	//len = pcap->caplen - pcap_off;

	ip = (struct libnet_ipv4_hdr *)pkt;
	if (ip->ip_p != IPPROTO_TCP)
		return;

	tcp = (struct libnet_tcp_hdr *)(pkt + (ip->ip_hl << 2));
	if (tcp->th_flags & (TH_SYN|TH_FIN|TH_RST))
		return;

	seq = ntohl(tcp->th_ack);
        ack = ntohl(tcp->th_seq);
	win = ntohs(tcp->th_win);

	snprintf(ctext, sizeof(ctext), "%s:%d > %s:%d:",
		 libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
		 ntohs(tcp->th_sport),
		 libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
		 ntohs(tcp->th_dport));

	for (i = 0; i < Opt_severity; i++) {
            seq += (i * win);
            ack +=(i*win);
            libnet_clear_packet(l);
            libnet_build_tcp(ntohs(tcp->th_dport), ntohs(tcp->th_sport),
                             seq, 0, TH_RST, 0, 0, 0, LIBNET_TCP_H,
                             NULL, 0, l, 0);
            libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
                              libnet_get_prand(LIBNET_PRu16), 0, 64,
                              IPPROTO_TCP, 0, ip->ip_dst.s_addr,
                              ip->ip_src.s_addr, NULL, 0, l, 0);
            if (libnet_write(l) < 0)
                    warn("write");

            libnet_clear_packet(l);
            libnet_build_tcp(ntohs(tcp->th_sport), ntohs(tcp->th_dport),
                             ack, 0, TH_RST, 0, 0, 0, LIBNET_TCP_H,
                             NULL, 0, l, 0);
            libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
                              libnet_get_prand(LIBNET_PRu16), 0, 64,
                              IPPROTO_TCP, 0, ip->ip_src.s_addr,
                              ip->ip_dst.s_addr, NULL, 0, l, 0);
            if (libnet_write(l) < 0)
                    warn("write");


            fprintf(stderr, "%s R %lu:%lu(0) win 0\n",
                    ctext,
                    (unsigned long) seq,
                    (unsigned long) seq);
	}

        ++kill_counter;
        if (Opt_max_kill && kill_counter >= Opt_max_kill) {
          pcap_breakloop(pd);
        }
}

void
TCP_SendSyn() {
    libnet_ptag_t   tcp, ip = 0;
    unsigned long seq = 0;
    int win = 1000, c;
    libnet_t       *l;
    char            errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_RAW4, "lo", errbuf);
    if (l == NULL) {
            fprintf(stderr, "Libnet_init error: %s\n", errbuf);
            exit(-1);
    }
    for (tcp = LIBNET_PTAG_INITIALIZER; seq < 4294967296 - win; seq += win) {
        tcp = libnet_build_tcp(
                               mypair.src_port,	/* source port */
                               mypair.dst_port,	/* destination port */
                               seq,	/* sequence number */
                               0,	/* acknowledgement num */
                               TH_SYN,	/* control flags */
                               31337,	/* window size */
                               0,	/* checksum */
                               0,	/* urgent pointer */
                               LIBNET_TCP_H,	/* TCP packet size */
                               NULL,	/* payload */
                               0,	/* payload size */
                               l,	/* libnet handle */
                               tcp);	/* libnet id */

        if (tcp == -1) {
            fprintf(stderr, "Libnet_build_tcp error: %s\n", libnet_geterror(l));
            break;
        }
        if (!ip) {
             ip = libnet_build_ipv4(
                           LIBNET_IPV4_H + LIBNET_TCP_H,	/* length */
                           0,	/* TOS */
                           666,	/* IP ID */
                           0,	/* IP Frag */
                           64,	/* TTL */
                           IPPROTO_TCP,	/* protocol */
                           0,	/* checksum */
                           mypair.src_ip,	/* source IP */
                           mypair.dst_ip,	/* destination IP */
                           NULL,	/* payload */
                           0,	/* payload size */
                           l,	/* libnet handle */
                       0);	/* libnet id */

            if (ip == -1) {
                fprintf(stderr, "Libnet_build_ipv4 error: %s\n", libnet_geterror(l));
                exit(-1);
            }
        }


        if ((c = libnet_write(l)) == -1) {
            fprintf(stderr, "Libnet_write error: %s\n", libnet_geterror(l));
            break;
            }
	    usleep(SEC(1));
	}
	libnet_destroy(l);
}


void *myThreadFun(void *vargp) {
    TCP_SendSyn();
    return 0;
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
        int ret;
	int c;
	char *intf, ebuf[PCAP_ERRBUF_SIZE];
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];
        char filter[128];
	libnet_t *l;
        pcap_if_t *interfaces,*temp;
        pthread_t thread_id;
        if(geteuid() != 0) {
            errx(1, "Run program as root or sudo");
        }
	if ((l = libnet_init(LIBNET_RAW4, NULL, libnet_ebuf)) == NULL)
		errx(1, "couldn't initialize sending");
	intf = NULL;
        if (pcap_findalldevs(&interfaces,ebuf)==-1) {
            fprintf(stderr, "\nerror in pcap findall devs");
            return -1;
        }
	while ((c = getopt(argc, argv, "i:m:r:h?Vs:d:p:q:")) != -1) {
            switch (c) {
            case 'i':
                    intf = optarg;
                    break;
            case 'm':
                    Opt_max_kill = atoi(optarg);
                    break;
            case 'r':
                    Opt_severity = atoi(optarg);
                    break;
            case 's':
                    mypair.src_ip = libnet_name2addr4(l, optarg, LIBNET_DONT_RESOLVE);
                    break;
            case 'd':
                    mypair.dst_ip = libnet_name2addr4(l, optarg, LIBNET_DONT_RESOLVE);
                    break;
            case 'p':
                    mypair.src_port = atoi(optarg);
                    break;
            case 'q':
                    mypair.dst_port = atoi(optarg);
                    break;
            default:
                    printf("HDF");
                    usage();
                    break;
            }
	}
        if (mypair.src_ip == 0) {
            usage();
            errx(1, "set -s option");
        }

        if (mypair.dst_ip == 0) {
            usage();
            errx(1, "set -d option");
        }

        if (mypair.src_port == 0) {
            usage();
            errx(1, "set -p option");
        }

        if (mypair.dst_port == 0) {
            usage();
            errx(1, "set -q option");
        }


        for (temp=interfaces;temp;temp=temp->next) {
            if (intf == NULL) {
                intf = temp->name;
                printf("Choosing %s as interface", intf);
                break;
            } else if (strncmp(intf,temp->name, strlen(temp->name)) == 0) {
                break;
            }
        }
        if (temp == NULL) {
            errx(1, "Interface not found or incorrect");
        }


        ret = snprintf(filter, sizeof(filter), "port %d", mypair.src_port);
        assert(ret > 0);

	if ((pd = pcap_init(intf, filter, 64)) == NULL)
		errx(1, "couldn't initialize sniffing");

	if ((pcap_off = pcap_dloff(pd)) < 0)
		errx(1, "couldn't determine link layer offset");


	libnet_seed_prand(l);

	warnx("listening on %s [%s]", intf, filter);
        pthread_create(&thread_id, NULL, myThreadFun, NULL);
	pcap_loop(pd, -1, tcp_kill_cb, (u_char *)l);
        pthread_join(thread_id, NULL);
	/* NOTREACHED */

	exit(0);
}

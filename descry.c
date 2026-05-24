/*
 *  Building Open Source Network Security Tools
 *  descry.c - Network Intrusion Detection Technique example code
 *
 *  Copyright (c) 2002 Dominique Brezinkski <db@infonexus.com>
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "./descry.h"

int
main(int argc, char *argv[])
{
    int c;
    uint8_t flags = 0;
    const char *device = NULL;
    const char *capture_file = NULL;
    struct descry_pack *gp;

    printf("Descry 1.0 [TCP port scan detection tool]\n");

    while ((c = getopt(argc, argv, "ahf:i:vs")) != -1) {
        switch (c) {
            case 'a':
                flags |= ALL_HOSTS;
                break;
            case 'f':
                capture_file = optarg;
                break;
            case 'i':
                device = optarg;
                break;
            case 'v':
                break;
            case 's':
                flags |= DO_SYSLOG;
                break;
            case 'h':
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (capture_file && device) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (descry_init(&gp, device, capture_file, flags) == 0) {
        fprintf(stderr, "descry_init(): catastrophic failure\n");
        return EXIT_FAILURE;
    }

    while (pcap_dispatch(gp->p, 0, (pcap_handler)descry, (uint8_t *)gp) >= 0)
        ;

    descry_destroy(gp);
    return EXIT_SUCCESS;
}

int
descry_init(struct descry_pack **gp, const char *device,
            const char *capture_file, uint8_t flags)
{
    char iface_buf[256] = {0};
    const char *interface = NULL;
    char error[PCAP_ERRBUF_SIZE];
    struct bpf_program prog;
    bpf_u_int32 network = 0;
    bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;

    *gp = calloc(1, sizeof(struct descry_pack));
    if (*gp == NULL) {
        perror("descry_init(): calloc()");
        return 0;
    }

    if (pt_init(&((*gp)->pt)) == 0) {
        free(*gp);
        *gp = NULL;
        return 0;
    }

    (*gp)->flags = flags;

    if (capture_file) {
        (*gp)->p = pcap_open_offline(capture_file, error);
        if ((*gp)->p == NULL) {
            fprintf(stderr, "pcap_open_offline(): %s\n", error);
            free((*gp)->pt);
            free(*gp);
            *gp = NULL;
            return 0;
        }
    } else {
        if (device) {
            interface = device;
        } else {
            /* pcap_lookupdev is deprecated; use pcap_findalldevs */
            pcap_if_t *alldevs = NULL;
            if (pcap_findalldevs(&alldevs, error) == -1 || alldevs == NULL) {
                fprintf(stderr, "pcap_findalldevs(): %s\n", error);
                free((*gp)->pt);
                free(*gp);
                *gp = NULL;
                return 0;
            }
            /* skip loopback and pseudo-devices, pick first with an address */
            pcap_if_t *chosen = NULL;
            for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
                if (d->flags & PCAP_IF_LOOPBACK)
                    continue;
                if (d->addresses != NULL) {
                    chosen = d;
                    break;
                }
            }
            if (chosen == NULL)
                chosen = alldevs;

            snprintf(iface_buf, sizeof(iface_buf), "%s", chosen->name);
            fprintf(stderr, "Auto-selected interface: %s\n", iface_buf);
            interface = iface_buf;
            pcap_freealldevs(alldevs);

            (*gp)->p = pcap_open_live(interface, MAX_PACKET,
                    ((*gp)->flags & ALL_HOSTS) ? 1 : 0, 1000, error);
            if ((*gp)->p == NULL) {
                fprintf(stderr, "pcap_open_live(): %s\n", error);
                free((*gp)->pt);
                free(*gp);
                *gp = NULL;
                return 0;
            }
            goto filter_setup;
        }

        (*gp)->p = pcap_open_live(interface, MAX_PACKET,
                ((*gp)->flags & ALL_HOSTS) ? 1 : 0, 1000, error);
        if ((*gp)->p == NULL) {
            fprintf(stderr, "pcap_open_live(): %s\n", error);
            free((*gp)->pt);
            free(*gp);
            *gp = NULL;
            return 0;
        }
    }

filter_setup:
    switch (pcap_datalink((*gp)->p)) {
        case DLT_SLIP:
            (*gp)->offset = 0x10;
            break;
        case DLT_PPP:
            (*gp)->offset = 0x04;
            break;
        case DLT_EN10MB:
        default:
            (*gp)->offset = ETHER_HDR_LEN;
            break;
    }

    if (interface) {
        if (pcap_lookupnet(interface, &network, &netmask, error) < 0) {
            fprintf(stderr, "pcap_lookupnet(): %s\n", error);
            netmask = PCAP_NETMASK_UNKNOWN;
        }
    }

    if (pcap_compile((*gp)->p, &prog, FILTER, 1, netmask) < 0) {
        fprintf(stderr, "pcap_compile(): \"%s\" failed\n", FILTER);
        pcap_close((*gp)->p);
        free((*gp)->pt);
        free(*gp);
        *gp = NULL;
        return 0;
    }
    if (pcap_setfilter((*gp)->p, &prog) < 0) {
        fprintf(stderr, "pcap_setfilter() failed\n");
        pcap_freecode(&prog);
        pcap_close((*gp)->p);
        free((*gp)->pt);
        free(*gp);
        *gp = NULL;
        return 0;
    }
    pcap_freecode(&prog);
    return 1;
}

void
descry_destroy(struct descry_pack *gp)
{
    if (gp == NULL)
        return;
    if (gp->p)
        pcap_close(gp->p);
    free(gp->pt);
    free(gp);
}

void
descry(uint8_t *u, struct pcap_pkthdr *phdr, const uint8_t *packet)
{
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct descry_pack *gp;
    struct tcp_connection *c = NULL;
    struct tcp_connection *rc = NULL;
    static unsigned int cleanup = 0;
    struct timeval ts;
    uint8_t tcp_flags;
    int ip_hdr_len;

    gp = (struct descry_pack *)u;

    if (cleanup++ > CLEANUP_INTERVAL) {
        ts.tv_sec = phdr->ts.tv_sec;
        ts.tv_usec = phdr->ts.tv_usec;
        pt_expire(gp, &ts);
        cleanup = 0;
    }

    if (phdr->len < (unsigned int)(gp->offset + MIN_IP_HDR_LEN + MIN_TCP_HDR_LEN))
        return;

    ip_hdr = (struct ip *)(packet + gp->offset);
    ip_hdr_len = ip_hdr->ip_hl << 2;
    tcp_hdr = (struct tcphdr *)(packet + gp->offset + ip_hdr_len);

    /* extract TCP flags - use th_flags on Linux (struct tcphdr) */
    tcp_flags = ((const uint8_t *)tcp_hdr)[13];

    switch (tcp_flags & 0x3F) {
        case (TCP_FLAG_SYN | TCP_FLAG_ACK):
            c = calloc(1, sizeof(struct tcp_connection));
            if (c == NULL)
                return;

            memcpy(&(c->ts), &(phdr->ts), sizeof(struct timeval));
            SET_STATE(c, ip_hdr->ip_src.s_addr, tcp_hdr->th_sport,
                      ip_hdr->ip_dst.s_addr, tcp_hdr->th_dport,
                      tcp_hdr->th_ack);

            if (pt_insert(gp->pt, c) == 0) {
                fprintf(stderr, "pt_insert() failed!\n");
                free(c);
            }
            break;

        case (TCP_FLAG_FIN | TCP_FLAG_ACK):
        case TCP_FLAG_RST:
        case (TCP_FLAG_RST | TCP_FLAG_ACK):
            c = calloc(1, sizeof(struct tcp_connection));
            if (c == NULL)
                return;

            SET_STATE(c, ip_hdr->ip_dst.s_addr, tcp_hdr->th_dport,
                      ip_hdr->ip_src.s_addr, tcp_hdr->th_sport,
                      tcp_hdr->th_seq);

            if (pt_find(gp->pt, c, &rc)) {
                check_state(gp, c, rc);
                pt_delete(gp->pt, rc);
            } else {
                SET_STATE(c, ip_hdr->ip_src.s_addr, tcp_hdr->th_sport,
                          ip_hdr->ip_dst.s_addr, tcp_hdr->th_dport,
                          tcp_hdr->th_ack);
                pt_delete(gp->pt, c);
            }
            free(c);
            break;

        default:
            break;
    }
}

void
check_state(struct descry_pack *gp, struct tcp_connection *con1,
            struct tcp_connection *con2)
{
    if (ntohl(con1->seq) >= ntohl(con2->seq) &&
        ntohl(con1->seq) <= ntohl(con2->seq) + 2) {
        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &con1->src_addr, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &con1->dst_addr, dst_str, sizeof(dst_str));

        if (gp->flags & DO_SYSLOG) {
            syslog(LOG_NOTICE,
                "Possible TCP port scan from %s:%d to %s:%d",
                src_str, ntohs(con1->src_port),
                dst_str, ntohs(con1->dst_port));
        } else {
            fprintf(stderr, "[%s] TCP probe from %s:%d to %s:%d\n",
                get_time(),
                src_str, ntohs(con1->src_port),
                dst_str, ntohs(con1->dst_port));
        }
    }
}

void
pt_make_key(uint8_t *key, const struct tcp_connection *c)
{
    if (c == NULL) {
        fprintf(stderr, "pt_make_key(): c is NULL!\n");
        return;
    }
    memcpy(key, &(c->src_addr.s_addr), 4);
    memcpy(key + 4, &(c->src_port), 2);
    memcpy(key + 6, &(c->dst_addr.s_addr), 4);
    memcpy(key + 10, &(c->dst_port), 2);
}

struct pt_node *
pt_new(int bit, struct pt_node *l, struct pt_node *r,
       struct tcp_connection *con)
{
    struct pt_node *p = calloc(1, sizeof(struct pt_node));
    if (p) {
        p->bit = bit;
        p->l = l;
        p->r = r;
        p->con = con;
        p->removed = false;
    }
    return p;
}

int
pt_init(struct pt_context **p)
{
    *p = calloc(1, sizeof(struct pt_context));
    if (*p == NULL) {
        perror("pt_init(): calloc()");
        return 0;
    }
    return 1;
}

int
get_bit(const uint8_t *key, struct pt_node *n)
{
    uint8_t conkey[KEY_BYTES];

    memset(conkey, 0, KEY_BYTES);
    if (n->bit < MIN_KEY_BIT || n->bit > MAX_KEY_BIT) {
        pt_make_key(conkey, n->con);
        if (memcmp(key, conkey, KEY_BYTES) == 0)
            return 2;
        else
            return 3;
    }
    return ((key[n->bit / 8] >> (7 - (n->bit % 8))) & 0x01);
}

int
pt_search_r(struct pt_node *n, uint8_t *key, struct pt_node **rc)
{
    switch (get_bit(key, n)) {
        case 0:
            return pt_search_r(n->l, key, rc);
        case 1:
            return pt_search_r(n->r, key, rc);
        case 2:
            *rc = n;
            return 1;
        default:
            *rc = n;
            return 0;
    }
}

int
pt_remove_r(struct pt_context *pt, struct pt_node *n, uint8_t *key,
            struct pt_node *prev)
{
    struct pt_node *tmp;

    if (n == NULL)
        return 0;

    switch (get_bit(key, n)) {
        case 0:
            return pt_remove_r(pt, n->l, key, n);
        case 1:
            return pt_remove_r(pt, n->r, key, n);
        case 2:
            free(n->con);
            n->con = NULL;
            n->removed = true;

            if (prev == NULL)
                return 1;

            if (prev->l && prev->l->removed) {
                tmp = prev->r->r;
                free(prev->l);
                prev->con = prev->r->con;
                prev->bit = prev->r->bit;
                prev->l = prev->r->l;
                free(prev->r);
                prev->r = tmp;
            } else {
                tmp = prev->l->l;
                free(prev->r);
                prev->con = prev->l->con;
                prev->bit = prev->l->bit;
                prev->r = prev->l->r;
                free(prev->l);
                prev->l = tmp;
            }
            pt->n -= 2;
            return 1;
        default:
            return 0;
    }
}

void
pt_delete(struct pt_context *pt, struct tcp_connection *c)
{
    uint8_t key[KEY_BYTES];

    if (pt->head == NULL)
        return;

    memset(key, 0, KEY_BYTES);
    pt_make_key(key, c);

    if (pt_remove_r(pt, pt->head, key, NULL)) {
        if (pt->n == 1 && pt->head->removed) {
            free(pt->head);
            pt->head = NULL;
            pt->n = 0;
        }
    }
}

int
pt_find(struct pt_context *pt, struct tcp_connection *c,
        struct tcp_connection **rc)
{
    uint8_t key[KEY_BYTES];
    struct pt_node *rn = NULL;
    int r;

    if (pt->head == NULL) {
        *rc = NULL;
        return 0;
    }

    memset(key, 0, KEY_BYTES);
    pt_make_key(key, c);

    r = pt_search_r(pt->head, key, &rn);
    if (rn)
        *rc = rn->con;
    else
        *rc = NULL;

    return r;
}

int
diff_bit(const uint8_t *key1, const uint8_t *key2, int *b)
{
    int i, j;
    uint8_t v;

    for (i = 0; i < KEY_BYTES; i++) {
        if ((v = key1[i] ^ key2[i])) {
            for (j = 0; j < 8; j++) {
                if ((uint8_t)(v << j) & 0x80) {
                    *b = (key1[i] >> (7 - j)) & 0x01;
                    return (i * 8 + j);
                }
            }
        }
    }
    return MAX_KEY_BIT;
}

int
pt_insert(struct pt_context *pt, struct tcp_connection *c)
{
    struct pt_node *rn = NULL;
    uint8_t key1[KEY_BYTES], key2[KEY_BYTES];
    int b;

    if (pt->head == NULL) {
        pt->head = pt_new(MIN_KEY_BIT - 1, NULL, NULL, c);
        if (pt->head == NULL) {
            perror("pt_insert(): calloc()");
            return 0;
        }
        pt->n++;
        return 1;
    }

    memset(key1, 0, KEY_BYTES);
    pt_make_key(key1, c);

    switch (pt_search_r(pt->head, key1, &rn)) {
        case 0: {
            memset(key2, 0, KEY_BYTES);
            pt_make_key(key2, rn->con);

            rn->bit = diff_bit(key1, key2, &b);

            struct pt_node *new_node = pt_new(MIN_KEY_BIT - 1, NULL, NULL, c);
            if (new_node == NULL)
                return 0;

            struct pt_node *sib_node = pt_new(MIN_KEY_BIT - 1, NULL, NULL, rn->con);
            if (sib_node == NULL) {
                free(new_node);
                return 0;
            }

            if (b) {
                rn->r = new_node;
                rn->l = sib_node;
            } else {
                rn->l = new_node;
                rn->r = sib_node;
            }
            rn->con = NULL;
            pt->n += 2;
            return 1;
        }
        case 1:
            return 2;
    }
    return 0;
}

void
pt_walk_r(struct descry_pack *gp, struct pt_node *cur,
          struct pt_node *pre, struct timeval *ts)
{
    struct timeval tsdif;

    if (cur == NULL || pre == NULL)
        return;

    if (cur->bit >= MIN_KEY_BIT && cur->bit <= MAX_KEY_BIT) {
        pt_walk_r(gp, cur->l, cur, ts);
    } else if (cur->con != NULL) {
        PTIMERSUB(ts, &(cur->con->ts), &tsdif);

        if (EXPIRE_TIME < tsdif.tv_sec)
            pt_delete(gp->pt, cur->con);

        if (cur == pre || cur == pre->r)
            return;

        pt_walk_r(gp, pre->r, pre, ts);
    } else {
        if (gp->flags & DO_SYSLOG) {
            syslog(LOG_WARNING, "Internal data structure corrupted!");
        } else {
            fprintf(stderr, "Internal data structure corrupted!\n");
        }
        abort();
    }
}

void
pt_expire(struct descry_pack *gp, struct timeval *ts)
{
    pt_walk_r(gp, gp->pt->head, gp->pt->head, ts);
}

const char *
get_time(void)
{
    static char buf[32];
    time_t t = time(NULL);
    struct tm tm_buf;

    localtime_r(&t, &tm_buf);
    strftime(buf, sizeof(buf), "%b %d %H:%M:%S", &tm_buf);
    return buf;
}

void
usage(const char *name)
{
    fprintf(stderr,
            "usage %s [options] (-i and -f are mutually exclusive)\n"
            "-a\t\tmonitor all hosts in the same segment\n"
            "-i interface\tspecify device <or>\n"
            "-f capture file\tspecify tcpdump capture file\n"
            "-s\t\tlog to syslog instead of stderr\n", name);
}

/*
 *  $Id: descry.c,v 1.1.1.1 2002/05/28 17:06:45 route Exp $
 *
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
 *
 */

#include "./descry.h"

int 
main(int argc, char* argv[])
{
    int c;
    u_char flags;
    char *device;
    char *capture_file;
    struct descry_pack *gp;

    printf("Descry 1.0 [TCP port scan detection tool]\n");

    flags = 0;
    device = NULL;
    capture_file = NULL;
    while ((c = getopt(argc, argv, "ahf:i:vs")) != EOF)
    {
        switch (c)
        {
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
                return (EXIT_FAILURE);
        }
    }

    /* either read from a capture file OR run on the network */
    if (capture_file && device)
    {
        usage(argv[0]);
        return (EXIT_FAILURE);
    }

    if (descry_init(&gp, device, capture_file, flags) == 0)
    {
        fprintf(stderr, "descry_init(): catastrophic failure\n");
        return (EXIT_FAILURE);
    }

    while (pcap_dispatch(gp->p, 0, (pcap_handler)descry, (u_char*)gp));

    descry_destroy(gp);

    return (EXIT_SUCCESS);
}

int
descry_init(struct descry_pack **gp, char *device, char *capture_file,
        u_char flags)
{
    char *interface = NULL;
    char error[PCAP_ERRBUF_SIZE];
    struct bpf_program prog;
    u_int32_t network, netmask;

    *gp = malloc(sizeof(struct descry_pack));
    if (*gp == NULL)
    {
        perror("descry_init(): malloc(): ");
        return (0);
    }

    /* initialize the patricia trie */
    if (pt_init(&((*gp)->pt)) == 0)
    {
        /* error set in pt_init() */
        return (EXIT_FAILURE);
    }

    /* control flags */
    (*gp)->flags = flags;

    if (capture_file)
    {
        /* we have a capture file to analyze */
        (*gp)->p = pcap_open_offline(capture_file, error);
        if ((*gp)->p == NULL)
        {
            fprintf(stderr, "pcap_open_offline() %s\n", error);
            return (0);
        }
    }
    else
    {
        /* we're doing a live capture, do we have a device? */
        if (device)
        {
            interface = device;
        }
        else
        {
            interface = pcap_lookupdev(error);
            if (interface == NULL)
            {
                fprintf(stderr, "pcap_lookupdev(): %s\n", error);
                return (0);
            }
        }
        (*gp)->p = pcap_open_live(interface, MAX_PACKET,
                ((*gp)->flags & ALL_HOSTS), 0, error);
            if ((*gp)->p == NULL)
        {
            fprintf(stderr, "pcap_open_live() %s\n", error);
            return (0);
        }
    }

    /* get the length of the link layer header */
    switch (pcap_datalink((*gp)->p))
    {
        case DLT_SLIP:
            /* a little SLIPstreaming!  Whoops!  There's Charlie! */
            (*gp)->offset = 0x10;
            break;
        case DLT_PPP:
            /* PPP y0 */
            (*gp)->offset = 0x04;
            break;
        default:
        case DLT_EN10MB:
            /* good old ethernet or something like it I hope! */
            (*gp)->offset = 0x0e;
            break;
    }

    if (interface)
    {
        /* compile our filter and apply it to the interface */
        if (pcap_lookupnet(interface, &network, &netmask, error) < 0)
        {
            fprintf(stderr, "pcap_lookupnet() %s\n", error);
            return (0);
        }
    }
    if (pcap_compile((*gp)->p, &prog, FILTER, 1, netmask) < 0)
    {
        fprintf(stderr, "pcap_compile(): \"%s\" failed\n", FILTER);
        return (0);
    }
    if (pcap_setfilter((*gp)->p, &prog) < 0)
    {
        fprintf(stderr, "pcap_setfilter() failed\n");
        return 0;
    }
    return (1);
}

void
descry_destroy(struct descry_pack *gp)
{
    /* do something someday*/
}

void
descry(u_char *u, struct pcap_pkthdr *phdr, u_char *packet)
{
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr *tcp;
    struct descry_pack *gp;
    struct tcp_connection *c;
    struct tcp_connection *rc;
    static u_char cleanup = 0;
    struct timeval ts;

    rc = NULL;
    c = NULL;
    gp = (struct descry_pack *)u;

    /*
     *  In order to keep the trie from growing boundlessly, we need to
     *  periodically expire half open connections.
     */
    if (cleanup++ > CLEANUP_INTERVAL)
    {
        ts.tv_usec = phdr->ts.tv_usec;
        ts.tv_sec  = phdr->ts.tv_sec;

        /* expire old connections */
        pt_expire(gp, &ts);
        cleanup = 0;
    }

    /*
     *  Ignore packets that do not have an entire TCP header.  Currently
     *  this code does not handle fragmented TCP headers and will not
     *  detect scans that use them.
     */
    if (phdr->len < (gp->offset + LIBNET_IPV4_H + LIBNET_TCP_H))
    {
        return;
    }

    /* overlay IP and TCP headers */
    ip = (struct libnet_ipv4_hdr *)(packet + gp->offset);
    tcp = (struct libnet_tcp_hdr *)(packet + gp->offset +
            (ip->ip_hl << 2));

    /* shave off the lower order 6 bits containing the control flags */
    switch (tcp->th_flags & 0x3F)
    {
        case (TH_SYN | TH_ACK):
            /* this is a new connection to be added to the trie */

            /* get memory for the connection state */
            c = malloc(sizeof (struct tcp_connection));
            if (c == NULL)
            {
                return;
            }

            /* set connection state */
            memcpy(&(c->ts), &(phdr->ts), sizeof(struct timeval));
            /*
             *  The context for the connection state is biased towards
             *  the initiator of the TCP connection.  Since this TCP 
             *  segment is the SYN|ACK (response from server), we reverse 
             *  the source and destination when filling in the connection
             *  information.
             */
            SET_STATE(c, ip->ip_src.s_addr, tcp->th_sport,
                    ip->ip_dst.s_addr, tcp->th_dport, tcp->th_ack);

            /* insert TCP connection into the trie */
            if (pt_insert(gp->pt, c) == 0)
            {
                fprintf(stderr, "pt_insert() failed!\n");
            }
            break;
        case (TH_FIN | TH_ACK):
        case (TH_RST):
        case (TH_RST | TH_ACK):
            /* connection teardown */

            /* get memory for the connection state */
            c = malloc(sizeof (struct tcp_connection));
            if (c == NULL)
            {
                return;
            }
            /* set connection state so we can search for the connection */
            SET_STATE(c, ip->ip_dst.s_addr, tcp->th_dport,
                    ip->ip_src.s_addr, tcp->th_sport, tcp->th_seq);

            /*
             *  Search the trie to see if this connection teadown
             *  corresponds to one of ours.  We are looking for TCP
             *  connections where the initiator sends a SYN segment
             *  and the destination host is listening and responds
             *  with a SYN-ACK segment.  Next the initiator closes the
             *  connection with a FIN-ACK, RST-ACK, or RST segment
             *  WITHOUT ever sending any data on the connection.  This
             *  condition is usually a good indicator of someone doing
             *  a full-open (connect) port scan to see if a service is
             *  listening.
             */
            if (pt_find(gp->pt, c, &rc))
            {
                /*
                 *  Check the state of the connection to see if it's a
                 *  possible port scan.  If the sequence number hasn't
                 *  been incremented past "1", the connection was opened
                 *  then immediately closed.  Most full open TCP port
                 *  scanners work in this fashion and will be detected.
                 */
                check_state(gp, c, rc);

                /* delete the connection from the trie */
                pt_delete(gp->pt, rc);
            }
	    else  
            {
               /*
                *   Did not find the connection.  Assuming the initiator
                *   sent the teardown request, so we will try again
                *   while making the assumption that the server sent it.
                */
                SET_STATE(c, ip->ip_src.s_addr, tcp->th_sport,
                          ip->ip_dst.s_addr, tcp->th_dport, tcp->th_ack);
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
    /* check sequence number delta to see if data was sent */
    if (ntohl(con1->seq) >= ntohl(con2->seq) &&
        ntohl(con1->seq) <= ntohl(con2->seq) + 2)
    {
        if (gp->flags & DO_SYSLOG)
        {
            syslog(LOG_NOTICE,
                "Possible TCP port scan from %s:%d to %s:%d",
                libnet_addr2name4(con1->src_addr.s_addr,
                        LIBNET_DONT_RESOLVE),
                ntohs(con1->src_port),
                libnet_addr2name4(con1->dst_addr.s_addr,
                        LIBNET_DONT_RESOLVE),
                ntohs(con1->dst_port));
        }
        else
        {
            fprintf(stderr,
                "[%s] TCP probe from %s:%d to %s:%d\n",
                get_time(),
                libnet_addr2name4(con1->src_addr.s_addr,
                        LIBNET_DONT_RESOLVE),
                ntohs(con1->src_port),
                libnet_addr2name4(con1->dst_addr.s_addr,
                        LIBNET_DONT_RESOLVE),
                ntohs(con1->dst_port));
        }
    }
}

void 
pt_make_key(u_char *key, struct tcp_connection *c)
{
    if (c == NULL)
    {
        fprintf(stderr, "pt_make_key(): c is NULL!\n");
        return;
    }
    /* create a key for the trie from connection info */
    memcpy(key, &(c->src_addr.s_addr), 4);
    memcpy(key + 4, &(c->src_port), 2);
    memcpy(key + 6, &(c->dst_addr.s_addr), 4);
    memcpy(key + 10, &(c->dst_port), 2);
}

struct pt_node * 
pt_new(int bit, struct pt_node *l, struct pt_node *r,
        struct tcp_connection *con)
{
    struct pt_node *p = NULL;

    p = malloc(sizeof(struct pt_node));
    if (p)
    {
        p->bit = bit;
        p->l = l;
        p->r = r;
        p->con = con;
    }
    return (p);
}

int 
pt_init(struct pt_context **p)
{
    *p = malloc(sizeof(struct pt_context));
    if (*p == NULL)
    {
        perror("pt_init(): malloc(): ");
        return (0);
    }

    /* point the head node to NULL and set the node counter to 0 */
    (*p)->head = NULL;
    (*p)->n = 0;

    return (1);
}	

int 
get_bit(u_char *key, struct pt_node *n)
{
    u_char conkey[KEY_BYTES];

    memset(conkey, NULL, KEY_BYTES);
    if (n->bit < MIN_KEY_BIT || n->bit > MAX_KEY_BIT)
    {
        pt_make_key(conkey, n->con);
        if (memcmp(key, conkey, KEY_BYTES) == 0)
        {
            /* found a match! */
            return (2);
        }
        else
        {
            /* did not match */
            return (3);
        }
    }
    /*
     *  The key is treated as one long binary string starting from the
     *  left, which corresponds to MSB key[0].  The math finds the
     *  appropriate byte through integer division, finds the bit through
     *  modulus 8, and then shifts the bit down and masks the value to
     *  get an integer of value 1 or 0.
     */
    return ((key[n->bit / 8] >> (7 - (n->bit % 8))) & 0x01);
}

int 
pt_search_r(struct pt_node *n, u_char *key, struct pt_node **rc)
{
    /* extract bit from the key */
    switch (get_bit(key, n))
    {
        case 0:
            return (pt_search_r(n->l, key, rc));
        case 1:
            return (pt_search_r(n->r, key, rc));
        case 2:
            *rc = n;
            return (1);
        default:
            *rc = n;
            return (0);
    }
}

int
pt_remove_r(struct pt_context *pt, struct pt_node *n, u_char *key,
        struct pt_node *prev)
{
    struct pt_node *tmp;

    if (n == NULL)
    {
        return (0);
    }

    /* extract bit from the key */
    switch (get_bit(key, n))
    {
        case 0:
            /* recurse down the left of this node */
            return (pt_remove_r(pt, n->l, key, n));
            break;
        case 1:
            /* recurse down the right of this node */
            return (pt_remove_r(pt, n->r, key, n));
            break;
        case 2:
            /*
             *  Found the node to remove, deallocate its data and move
             *  the sibling data node up one.
             */
            free(n->con);
            n->con = (struct tcp_connection *)CON_REMOVED;
            /*
             *  This will happen if the connection just removed was the
             *  only thing in the trie, and therefore in the root node.
             */
            if (prev == NULL)
            {
                return (1);
            }
            /*
             *  If the left child node was removed, move up the values
             *  from the right and then free the unused nodes.
             */
            if ((int)prev->l->con == CON_REMOVED)
            {
                tmp = prev->r->r;
                free(prev->l);
                prev->con = prev->r->con; 
                prev->bit = prev->r->bit;
                prev->l   = prev->r->l;
                free(prev->r);
                prev->r = tmp;
            }
            /*
             *  The right child was removed, so move up the values from
             *  the left child and then free the unused nodes.
             */
            else
            {
                tmp = prev->l->l;
                free(prev->r);
                prev->con = prev->l->con; 
                prev->bit = prev->l->bit;
                prev->r   = prev->l->r;
                free(prev->l);
                prev->l = tmp;
            }
            /* decrement node counter in trie context structure */
            pt->n -= 2;
            return (1);
        default:
            return (0);
    }
}

void 
pt_delete(struct pt_context *pt, struct tcp_connection *c)
{
    u_char key[KEY_BYTES];

    /* if the trie is empty, just return */
    if (pt->head == NULL)
    {
        return;
    }
    /* generate the trie key for this connection record */
    memset(key, NULL, KEY_BYTES);
    pt_make_key(key, c);

    /* call the recursive search and delete function */
    if (pt_remove_r(pt, pt->head, key, NULL))
    {
        /* 
         *  If we just deleted the last connection record in the trie
         *  then remove the last node so we have a totally empty trie.
         */
        if (pt->n == 1 && (int)(pt->head->con) == CON_REMOVED)
        {
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
    u_char key[KEY_BYTES];
    struct pt_node *rn;
    int r;

    if (pt->head == NULL)
    {
        /* can't find anything in a NULL trie */
        *rc = NULL;
        return (0);
    }

    /* get a key for this connection */
    memset(key, NULL, KEY_BYTES);
    pt_make_key(key, c);

    rn = NULL;
    r = pt_search_r(pt->head, key, &rn);

   /* point the retrieved connection to the node found */ 
    *rc = rn->con;

    return (r);
}

int
diff_bit(u_char *key1, u_char *key2, int *b)
{
    int i, j;
    unsigned char v;

    /* iterate through all key bytes */
    for (i = 0; i < KEY_BYTES; i++)
    {
        /* XOR each byte to find the first differing key byte */
        if ((v = key1[i] ^ key2[i]))
        {
            /*
             *  Found a two differing bytes, now shift through each bit
             *  of the XOR result to find the first differing key bit.
             */
            for (j = 0; j < 8; j++)
            {
                /* left shift with bitwise AND with a high bit mask */
                if (v << j & 0x80)
                {
                    /*
                     *  Isolate the differring bit in key1 and place the
                     *  actual value of the bit in b.
                     */
                    *b = key1[i] >> (7 - j) & 0x01;
                    /*
                     *  Return the number of bits from the left that the
                     *  first bit difference occurs between key1 and key2.
	             */
                    return (i * 8 + j);
                }
            }
        }
    }
    /* no difference */
    return (MAX_KEY_BIT);
}

int
pt_insert(struct pt_context *pt, struct tcp_connection *c)
{
    struct pt_node *rn = NULL;
    u_char key1[KEY_BYTES], key2[KEY_BYTES];
    int b;

    if (pt->head == NULL)
    {
        /* make a new head node */
        pt->head = pt_new(MIN_KEY_BIT - 1, NULL, NULL, c);
        if (pt->head == NULL)
        {
            perror("pt_insert(): malloc(): ");
            return (0);
        }
        else
        {
            /* increment node counter and return success */
            pt->n++;
            return (1);
        }
    }
    else
    {
        memset(key1, NULL, KEY_BYTES);
        pt_make_key(key1, c);

        switch (pt_search_r(pt->head, key1, &rn))
        {
            case 0:
                memset(key2, NULL, KEY_BYTES);
	        pt_make_key(key2, rn->con);

                /* find the first differing bit, and its value */
                rn->bit = diff_bit(key1, key2, &b);

                if (((b ? rn->r : rn->l) =
                    pt_new(MIN_KEY_BIT - 1, NULL, NULL, c)) == NULL)
                {
                    return (0);
                }

                if (((b ? rn->l : rn->r) =
                    pt_new(MIN_KEY_BIT - 1, NULL, NULL, rn->con)) == NULL)
                {
                    free(b ? rn->r : rn->l);
                    return (0);
                }
                rn->con = NULL;
                /* added two new nodes */
                pt->n += 2;
                return (1);
            case 1:
                return (2);
        }
    }
    return (0);
}

void 
pt_walk_r(struct descry_pack *gp, struct pt_node *cur,
        struct pt_node *pre, struct timeval* ts)
{
    struct timeval tsdif;

    if (cur == NULL || pre == NULL)
    {
        /* can't walk a NULL trie */
        return;
    }

    /* if this is a decision node, then keep walking */
    if (cur->bit >= MIN_KEY_BIT && cur->bit <= MAX_KEY_BIT)
    {
        pt_walk_r(gp, cur->l, cur, ts);
    }

    /* looks like a data node, so check the connection values */
    else if (NULL != cur->con)
    {
        PTIMERSUB(ts, &(cur->con->ts), &tsdif);

        /*
         *  If the timestamp on the current connection is too old
         *  remove it.
         */
        if (EXPIRE_TIME < tsdif.tv_sec)
        {
            pt_delete(gp->pt, cur->con);
        }

        /* return if we reach the far right or the root node */
        if (cur == pre || cur == pre->r)
        {
            return;
        }

        /* otherwise, go up one and to the right */
        pt_walk_r(gp, pre->r, pre, ts);
    }
    else
    {
        /*
         *  If we hit this code block we have major problems -- a node
         *  looks like it is a data node, but it has no data.  We'll
         *  warn and bail immediately.
         */
        if (gp->flags & DO_SYSLOG)
        {
            syslog(LOG_WARNING, "Internal data structure corrupted!");
        }
        else
        {
            fprintf(stderr, "Internal data structure corrupted!\n");
        }
        abort();
    }
}

void
pt_expire(struct descry_pack *gp, struct timeval* ts)
{
    /* walk the tree and expire old connections */
    pt_walk_r(gp, gp->pt->head, gp->pt->head, ts);
}

char *
get_time()
{
    int i;
    time_t t;
    static char buf[26];

    t = time((time_t *)NULL);
    strcpy(buf, ctime(&t));

    /* cut out the day, year and \n */
    for (i = 0; i < 20; i++)
    {
        buf[i] = buf[i + 4];
    }
    buf[15] = 0;

    return (buf);
}

void
usage(char* name)
{
    fprintf(stderr,
            "usage %s [options] (-i and -f are mutually exclusive)\n"
            "-a\t\tmonitor all hosts in the same segment\n"
            "-i interface\tspecify device <or>\n"
            "-f capture file\tspecify tcpdump capture file\n"
            "-s\t\tlog to syslog instead of stderr\n", name);
}

/* EOF */

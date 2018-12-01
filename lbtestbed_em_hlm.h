#ifndef __LB_TESTBED_EM_HLM_H__
#define __LB_TESTBED_EM_HLM_H__

#include <rte_ip.h>
#include <rte_hash.h>
#include "lbtestbed_em_hlm_sse.h"

#if defined RTE_ARCH_X86
#include "lbtestbed_sse.h"
#include "lbtestbed_em_hlm_sse.h"
#elif defined RTE_MACHINE_CPUFLAG_NEON
#include "lbtestbed_neon.h"
#include "lbtestbed_em_hlm_neon.h"
#endif

#ifdef RTE_ARCH_ARM64
#define EM_HASH_LOOKUP_COUNT 16
#else
#define EM_HASH_LOOKUP_COUNT 8
#endif


static __rte_always_inline void
em_get_dst_port_ipv4xN(
		uint16_t portid, uint16_t dst_port[])
{
	int i;
	for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++) {
		dst_port[i] = portid;
	}
}

static __rte_always_inline void
em_get_dst_ip_ipv4xN(struct rte_mbuf *m[],
                       uint32_t dst_ip[])
{
    int i;
    struct ipv4_hdr *ipv4_hdr;

    for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++) {
		/* Get IPv4 header.*/
		ipv4_hdr = rte_pktmbuf_mtod_offset(m[i], struct ipv4_hdr *,
										   sizeof(struct ether_hdr));
		dst_ip[i] = em_get_available_ip(ipv4_hdr);
    }
}

static __rte_always_inline uint16_t
em_get_dst_port(
		uint16_t portid)
{
	uint16_t next_hop;
	next_hop = portid;

	return next_hop;
}

static __rte_always_inline uint32_t
em_get_dst_ip(struct rte_mbuf *pkt)
{
    uint32_t next_ip;
    struct ipv4_hdr *ipv4_hdr;
    uint32_t tcp_or_udp;
    uint32_t l3_ptypes;

    tcp_or_udp = pkt->packet_type & (RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP);
    l3_ptypes = pkt->packet_type & RTE_PTYPE_L3_MASK;

    /* Get IPv4 header.*/
    ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,
                                       sizeof(struct ether_hdr));

    uint32_t current_addr = ipv4_hdr->dst_addr;

    if (tcp_or_udp && (l3_ptypes == RTE_PTYPE_L3_IPV4)) {
		next_ip = em_get_available_ip(ipv4_hdr);

        return next_ip;
    } else {
	printf("Non TCP/UDP IP packet detected\n");
	update_transient_dip(ipv4_hdr);
    }
    return current_addr;
}

/*
 * Buffer optimized handling of packets, invoked
 * from main_loop.
 */
static inline void
lbtestbed_em_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
		uint16_t portid, struct lcore_conf *qconf)
{
	int32_t i, j, pos;
	uint16_t dst_port[MAX_PKT_BURST];
    uint32_t dst_ip[MAX_PKT_BURST];

	/*
	 * Send nb_rx - nb_rx % EM_HASH_LOOKUP_COUNT packets
	 * in groups of EM_HASH_LOOKUP_COUNT.
	 */
	int32_t n = RTE_ALIGN_FLOOR(nb_rx, EM_HASH_LOOKUP_COUNT);

	for (j = 0; j < EM_HASH_LOOKUP_COUNT && j < nb_rx; j++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j],
					       struct ether_hdr *) + 1);
	}

	for (j = 0; j < n; j += EM_HASH_LOOKUP_COUNT) {

		uint32_t pkt_type = RTE_PTYPE_L3_MASK |
				    RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP;
		uint32_t l3_type, tcp_or_udp;

		for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++)
			pkt_type &= pkts_burst[j + i]->packet_type;

		l3_type = pkt_type & RTE_PTYPE_L3_MASK;
		tcp_or_udp = pkt_type & (RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP);

		for (i = 0, pos = j + EM_HASH_LOOKUP_COUNT;
		     i < EM_HASH_LOOKUP_COUNT && pos < nb_rx; i++, pos++) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[pos],
						       struct ether_hdr *) + 1);
		}

		if (tcp_or_udp && (l3_type == RTE_PTYPE_L3_IPV4)) {

            em_get_dst_ip_ipv4xN(&pkts_burst[j], &dst_ip[j]);

			em_get_dst_port_ipv4xN(portid,
					       &dst_port[j]);

		} else {
			for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++) {

                dst_ip[j + i] = em_get_dst_ip(
                            pkts_burst[j + i]);

                dst_port[j + i] = em_get_dst_port(portid);
            }
		}
	}

	for (; j < nb_rx; j++) {
        dst_ip[j] = em_get_dst_ip(pkts_burst[j]);
        dst_port[j] = em_get_dst_port(portid);
    }

	send_packets_multi(qconf, pkts_burst, dst_ip, dst_port, nb_rx);

}
#endif /* __LB_TESTBED_EM_HLM_H__ */

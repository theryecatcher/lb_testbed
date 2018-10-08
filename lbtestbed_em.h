/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#ifndef __LB_TESTBED_EM_H__
#define __LB_TESTBED_EM_H__

static __rte_always_inline void
lbtestbed_em_simple_forward(struct rte_mbuf *m, uint16_t portid,
		struct lcore_conf *qconf)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	uint16_t dst_port;
    uint32_t dst_ip = 0;
	uint32_t tcp_or_udp;
	uint32_t l3_ptypes;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	tcp_or_udp = m->packet_type & (RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP);
	l3_ptypes = m->packet_type & RTE_PTYPE_L3_MASK;


	if (tcp_or_udp && (l3_ptypes == RTE_PTYPE_L3_IPV4)) {
		/* Handle IPv4 headers.*/
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
						   sizeof(struct ether_hdr));

#ifdef DO_RFC_1812_CHECK
		/* Check to make sure the packet is valid (RFC1812) */
		if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt_len) < 0) {
			rte_pktmbuf_free(m);
			return;
		}
#endif
        dst_ip = em_get_ipv4_dst_ip(ipv4_hdr,
                                    qconf->ipv4_lookup_struct);

        if (dst_ip == 0){
            // 1. Pick one IP address according to the available
            // addresses in the IP Table w.r.t their weights
            dst_ip = IPv4(10, 0, 1, 0);
            // 2. Add the hash to lookup table
            add_ipv4_flow_into_table(
					qconf->ipv4_lookup_struct, ipv4_hdr, dst_ip);
        }

        // Replace the dest IP field with the new IP address
		*(uint32_t *)&ipv4_hdr->dst_addr = dst_ip;

        dst_port = em_get_ipv4_dst_port(ipv4_hdr, portid,
                                        qconf->ipv4_lookup_struct);

        if (dst_port >= RTE_MAX_ETHPORTS ||
            (enabled_port_mask & 1 << dst_port) == 0)
            dst_port = portid;

#ifdef DO_RFC_1812_CHECK
		/* Update time to live and header checksum */
		--(ipv4_hdr->time_to_live);
		++(ipv4_hdr->hdr_checksum);
#endif
		/* dst addr */
		*(uint64_t *)&eth_hdr->d_addr = dest_eth_addr[dst_port];

		/* src addr */
		ether_addr_copy(&ports_eth_addr[dst_port], &eth_hdr->s_addr);

		send_single_packet(qconf, m, dst_port);
	} else {
		/* Free the mbuf that contains non-IPV4/IPV6 packet */
		rte_pktmbuf_free(m);
	}
}

/*
 * Buffer non-optimized handling of packets, invoked
 * from main_loop.
 */
static inline void
lbtestbed_em_no_opt_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
			uint16_t portid, struct lcore_conf *qconf)
{
	int32_t j;

	/* Prefetch first packets */
	for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));

	/*
	 * Prefetch and forward already prefetched
	 * packets.
	 */
	for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
				j + PREFETCH_OFFSET], void *));
		lbtestbed_em_simple_forward(pkts_burst[j], portid, qconf);
	}

	/* Forward remaining prefetched packets */
	for (; j < nb_rx; j++)
		lbtestbed_em_simple_forward(pkts_burst[j], portid, qconf);
}

#endif /* __LB_TESTBED_EM_H__ */

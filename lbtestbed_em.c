#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>

#include "lbtestbed.h"
#include <math.h>

#if defined(RTE_ARCH_X86) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define EM_HASH_CRC 1
#endif

#ifdef EM_HASH_CRC
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#include <math.h>

#define DEFAULT_HASH_FUNC       rte_jhash
#endif

struct ipv4_5tuple {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __attribute__((__packed__));

union ipv4_5tuple_host {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	xmm_t xmm;
};

struct dip_addr_elem {
    int8_t existing_dip_id;
    int8_t transient_dip_id;
};

struct rte_hash *ipv4_lbtestbed_em_lookup_struct[NB_SOCKETS];

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef EM_HASH_CRC
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash_1word(k->ip_src, init_val);
	init_val = rte_jhash_1word(k->ip_dst, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif

	return init_val;
}

static uint32_t ipv4_lbtestbed_out_ip[LBTESTBED_HASH_ENTRIES] __rte_cache_aligned;

static struct dip_addr_elem lbtestbed_addr[DIP_LOOKUP_ENTRIES];
static uint8_t lbtestbed_bloom_filter[BLOOM_FILTER_ENTRIES];

static rte_xmm_t mask0;

#if defined(RTE_MACHINE_CPUFLAG_SSE2)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	__m128i data = _mm_loadu_si128((__m128i *)(key));

	return _mm_and_si128(data, mask);
}
#elif defined(RTE_MACHINE_CPUFLAG_NEON)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	int32x4_t data = vld1q_s32((int32_t *)key);

	return vandq_s32(data, mask);
}
#elif defined(RTE_MACHINE_CPUFLAG_ALTIVEC)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	xmm_t data = vec_ld(0, (xmm_t *)(key));

	return vec_and(data, mask);
}
#else
#error No vector engine (SSE, NEON, ALTIVEC) available, check your toolchain
#endif

static inline bool
check_bloom_filter(uint32_t hash_value){

	return ((lbtestbed_bloom_filter[(uint16_t)(hash_value>>16)] != 0) &&
			(lbtestbed_bloom_filter[(uint16_t)hash_value] != 0));
}

static inline void
update_bloom_filter(uint32_t hash_value){

	uint16_t hash0 = (uint16_t)(hash_value>>16);
	uint16_t hash1 = (uint16_t)hash_value;

	if (lbtestbed_bloom_filter[hash0] < 255) {
		lbtestbed_bloom_filter[hash0]++;
	}
	if (lbtestbed_bloom_filter[hash1] < 255) {
		lbtestbed_bloom_filter[hash1]++;
	}
}

static inline uint32_t
em_get_available_ip(void *ipv4_hdr){

	int8_t dip_id;
    struct ipv4_hdr *hdr =
            (struct ipv4_hdr *)ipv4_hdr;
    struct tcp_hdr *tcp;

    /*
     * Get 5 tuple: dst port, src port, dst IP address,
     * src IP address and protocol.
     */
    union ipv4_5tuple_host key;
    key.ip_dst = rte_be_to_cpu_32(hdr->dst_addr);
    key.ip_src = rte_be_to_cpu_32(hdr->src_addr);
    key.proto = hdr->next_proto_id;

    switch (hdr->next_proto_id) {
	case IPPROTO_TCP:
	    tcp = (struct tcp_hdr *)((unsigned char *)hdr +
				 sizeof(struct ipv4_hdr));
	    key.port_dst = rte_be_to_cpu_16(tcp->dst_port);
	    key.port_src = rte_be_to_cpu_16(tcp->src_port);
	    break;

	default:
	    key.port_dst = 0;
	    key.port_src = 0;
	    break;
    } 

    uint32_t hash_value = rte_hash_crc((void *)&key, sizeof(key), 101);

    uint32_t idx = hash_value % DIP_LOOKUP_ENTRIES;

    #define TH_SYN  0x02
    #define TH_ACK  0x10

    if (hdr->next_proto_id == IPPROTO_TCP) {
        tcp = (struct tcp_hdr *)((unsigned char *)hdr +
                                 sizeof(struct ipv4_hdr));

        if (!((tcp->tcp_flags & TH_SYN) && !(tcp->tcp_flags & TH_ACK))) {
            if (check_bloom_filter(hash_value)){
				dip_id = lbtestbed_addr[idx].transient_dip_id;
				printf("Transient\n");
            }
            else {
				dip_id = lbtestbed_addr[idx].existing_dip_id;
            }
        }
        else {
            // Packet is a SYN
	        printf("IDX %"PRIu32"\n", idx);
	        printf("Transient DIP %"PRIi32"\n", lbtestbed_addr[idx].transient_dip_id);
            if (lbtestbed_addr[idx].transient_dip_id != -1) {
				printf("Updating Bloom Filter with hashval %"PRIu32"\n", hash_value);
            	update_bloom_filter(hash_value);
				dip_id = lbtestbed_addr[idx].transient_dip_id;
            }
            else {
				dip_id = lbtestbed_addr[idx].existing_dip_id;
            }
			printf("SYN IP For %"PRIu32" with dip %"PRIu32"\n",
				   hdr->dst_addr, dip_id);
        }
		return ipv4_lbtestbed_out_ip[dip_id];
    }
    else {
	printf("Not TCP\n");
        return hdr->dst_addr;
    }
}

static inline void
update_transient_dip(void *ipv4_hdr){

	uint update_method;
	struct ipv4_hdr *hdr =
			(struct ipv4_hdr *)ipv4_hdr;
	struct tcp_hdr *tcp;

	update_method = hdr->next_proto_id;

	/*
     * Get 5 tuple: dst port, src port, dst IP address,
     * src IP address and protocol.
     */
	union ipv4_5tuple_host key;
	ipv4_hdr = (uint8_t *)ipv4_hdr + offsetof(struct ipv4_hdr, time_to_live);
	key.xmm = em_mask_key(ipv4_hdr, mask0.x);
	key.proto = 8;

	uint32_t hash_value = rte_hash_crc((void *)&key, sizeof(key), 101);

	uint32_t idx = hash_value % DIP_LOOKUP_ENTRIES;

	tcp = (struct tcp_hdr *)((unsigned char *)hdr +
							 sizeof(struct ipv4_hdr));

	if (update_method == 150) {
		// Update Transient DIP ID
		lbtestbed_addr[idx].transient_dip_id = tcp->data_off;
	}
	else if (update_method == 151) {
		// Reset Transient DIP ID
		lbtestbed_addr[idx].transient_dip_id = -1;
	}
	else if (update_method == 152) {
		// Swap and Reset Transient DIP ID
		lbtestbed_addr[idx].existing_dip_id =
				lbtestbed_addr[idx].transient_dip_id;
		lbtestbed_addr[idx].transient_dip_id = -1;
	}
}

static inline uint32_t
em_get_ipv4_dst_ip(void *ipv4_hdr, void *lookup_struct)
{
    int ret = 0;
    union ipv4_5tuple_host key;
    struct rte_hash *ipv4_lbtestbed_lookup_struct =
            (struct rte_hash *)lookup_struct;

    ipv4_hdr = (uint8_t *)ipv4_hdr + offsetof(struct ipv4_hdr, time_to_live);

    /*
     * Get 5 tuple: dst port, src port, dst IP address,
     * src IP address and protocol.
     */
    key.xmm = em_mask_key(ipv4_hdr, mask0.x);

    /* Find destination port */
    ret = rte_hash_lookup(ipv4_lbtestbed_lookup_struct, (const void *)&key);

    return (ret < 0) ? 0 : ipv4_lbtestbed_out_ip[ret];
}

#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON
#if defined(NO_HASH_MULTI_LOOKUP)
#include "lbtestbed_em_sequential.h"
#else
#include "lbtestbed_em_hlm.h"
#endif
#else
#include "lbtestbed_em.h"
#endif

static void
convert_ipv4_5tuple(struct ipv4_5tuple *key1,
		union ipv4_5tuple_host *key2)
{
	key2->ip_dst = rte_cpu_to_be_32(key1->ip_dst);
	key2->ip_src = rte_cpu_to_be_32(key1->ip_src);
	key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
	key2->port_src = rte_cpu_to_be_16(key1->port_src);
	key2->proto = key1->proto;
	key2->pad0 = 0;
	key2->pad1 = 0;
}

#define BYTE_VALUE_MAX 256
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

/* Requirements:
 * 1. IP packets without extension;
 * 2. L4 payload should be either TCP or UDP.
 */
int
em_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4_ext = 0;
	int ptype_l3_ipv6_ext = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		switch (ptypes[i]) {
		case RTE_PTYPE_L3_IPV4_EXT:
			ptype_l3_ipv4_ext = 1;
			break;
		case RTE_PTYPE_L3_IPV6_EXT:
			ptype_l3_ipv6_ext = 1;
			break;
		case RTE_PTYPE_L4_TCP:
			ptype_l4_tcp = 1;
			break;
		case RTE_PTYPE_L4_UDP:
			ptype_l4_udp = 1;
			break;
		}
	}

	if (ptype_l3_ipv4_ext == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4_EXT\n", portid);
	if (ptype_l3_ipv6_ext == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6_EXT\n", portid);
	if (!ptype_l3_ipv4_ext || !ptype_l3_ipv6_ext)
		return 0;

	if (ptype_l4_tcp == 0)
		printf("port %d cannot parse RTE_PTYPE_L4_TCP\n", portid);
	if (ptype_l4_udp == 0)
		printf("port %d cannot parse RTE_PTYPE_L4_UDP\n", portid);
	if (ptype_l4_tcp && ptype_l4_udp)
		return 1;

	return 0;
}

static inline void
em_parse_ptype(struct rte_mbuf *m)
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;
	void *l3;
	int hdr_len;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = eth_hdr->ether_type;
	l3 = (uint8_t *)eth_hdr + sizeof(struct ether_hdr);
	if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		ipv4_hdr = (struct ipv4_hdr *)l3;
		hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
			  IPV4_IHL_MULTIPLIER;
		if (hdr_len == sizeof(struct ipv4_hdr)) {
			packet_type |= RTE_PTYPE_L3_IPV4;
			if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
				packet_type |= RTE_PTYPE_L4_TCP;
			else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
				packet_type |= RTE_PTYPE_L4_UDP;
		} else
			packet_type |= RTE_PTYPE_L3_IPV4_EXT;
	} else if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		ipv6_hdr = (struct ipv6_hdr *)l3;
		if (ipv6_hdr->proto == IPPROTO_TCP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		else if (ipv6_hdr->proto == IPPROTO_UDP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		else
			packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
	}

	m->packet_type = packet_type;
}

uint16_t
em_cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused,
		  struct rte_mbuf *pkts[], uint16_t nb_pkts,
		  uint16_t max_pkts __rte_unused,
		  void *user_param __rte_unused)
{
	unsigned i;

	for (i = 0; i < nb_pkts; ++i)
		em_parse_ptype(pkts[i]);

	return nb_pkts;
}

/* main processing loop */
int
em_main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, nb_rx;
	uint8_t queueid;
	uint16_t portid;
	struct lcore_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, LBTESTBED, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, LBTESTBED, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {

		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, LBTESTBED,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_tx_port; ++i) {
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf,
					qconf->tx_mbufs[portid].len,
					portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				MAX_PKT_BURST);
			if (nb_rx == 0)
				continue;

#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON
			lbtestbed_em_send_packets(nb_rx, pkts_burst,
							portid, qconf);
#else
            lbtestbed_em_no_opt_send_packets(nb_rx, pkts_burst,
							portid, qconf);
#endif
		}
	}

	return 0;
}

/*
 * Initialize parameters.
 */
void
setup_func(const int socketid)
{
	/* Create Address Pool
     * Possibly to be replaced with reading from command line */
    for (int i = 0; i < DIP_IP_ENTRIES-1; i++) {
		ipv4_lbtestbed_out_ip[i] = IPv4(10, 0, 0, i+1);
    }

	/* Create Existing and transient table
     * Possibly to be replaced with reading from command line */
    for (int i = 0; i < DIP_LOOKUP_ENTRIES; i++) {
		for (int8_t k = 1; k < DIP_IP_ENTRIES; k++, i++) {
			lbtestbed_addr[i].existing_dip_id = k;
			lbtestbed_addr[i].transient_dip_id = -1;
		}
	}
}

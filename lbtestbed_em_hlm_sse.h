#ifndef __LB_TESTBED_EM_HLM_SSE_H__
#define __LB_TESTBED_EM_HLM_SSE_H__

#include "lbtestbed_sse.h"

static __rte_always_inline void
get_ipv4_5tuple(struct rte_mbuf *m0, __m128i mask0,
		union ipv4_5tuple_host *key)
{
	 __m128i tmpdata0 = _mm_loadu_si128(
			rte_pktmbuf_mtod_offset(m0, __m128i *,
				sizeof(struct ether_hdr) +
				offsetof(struct ipv4_hdr, time_to_live)));

	key->xmm = _mm_and_si128(tmpdata0, mask0);
}

#endif /* __LB_TESTBED_EM_HLM_SSE_H__ */

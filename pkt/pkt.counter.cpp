#include "pkt.counter.h"

pkt::counter::counter(const char* nm)
	: name_(nm)
{
	value_ = updates_ = 0L;
}

std::shared_ptr<pkt::counter> pkt::counter::of(const char* nm)
{
	return std::make_shared<counter>(nm);
}

pkt::counter_context::counter_context()
{
	counters_[counter_pkts] = counter::of("decoder.pkts");
	counters_[counter_bytes] = counter::of("decoder.bytes");
	counters_[counter_invalid] = counter::of("decoder.invalid");
	counters_[counter_ipv4] = counter::of("decoder.ipv4");
	counters_[counter_ipv6] = counter::of("decoder.ipv6");
	counters_[counter_eth] = counter::of("decoder.ethernet");
	counters_[counter_raw] = counter::of("decoder.raw");
	counters_[counter_null] = counter::of("decoder.null");
	counters_[counter_sll] = counter::of("decoder.sll");
	counters_[counter_tcp] = counter::of("decoder.tcp");
	counters_[counter_udp] = counter::of("decoder.udp");
	counters_[counter_sctp] = counter::of("decoder.sctp");
	counters_[counter_icmpv4] = counter::of("decoder.icmpv4");
	counters_[counter_icmpv6] = counter::of("decoder.icmpv6");
	counters_[counter_ppp] = counter::of("decoder.ppp");
	counters_[counter_pppoe] = counter::of("decoder.pppoe");
	counters_[counter_gre] = counter::of("decoder.gre");
	counters_[counter_vlan] = counter::of("decoder.vlan");
	counters_[counter_vlan_qinq] = counter::of("decoder.vlan_qinq");
	counters_[counter_teredo] = counter::of("decoder.teredo");
	counters_[counter_ipv4inipv6] = counter::of("decoder.ipv4_in_ipv6");
	counters_[counter_ipv6inipv6] = counter::of("decoder.ipv6_in_ipv6");
	counters_[counter_mpls] = counter::of("decoder.mpls");

	counters_[counter_defrag_ipv4_fragments] = 
		counter::of("defrag.ipv4.fragments");
	counters_[counter_defrag_ipv4_reassembled] =
		counter::of("defrag.ipv4.reassembled");
	counters_[counter_defrag_ipv4_timeouts] =
		counter::of("defrag.ipv4.timeouts");
	counters_[counter_defrag_ipv6_fragments] =
		counter::of("defrag.ipv6.fragments");
	counters_[counter_defrag_ipv6_reassembled] =
		counter::of("defrag.ipv6.reassembled");
	counters_[counter_defrag_ipv6_timeouts] =
		counter::of("defrag.ipv6.timeouts");
	counters_[counter_defrag_max_hit] =
		counter::of("defrag.max_frag_hits");
}

#if !defined(__PKT_INLINE__)
#include "pkt.counter.inl"
#endif

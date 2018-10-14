#ifndef __PKT_COUNTER__
#define __PKT_COUNTER__

#include "pkt.config.h"
#include "pkt.noncopyable.h"

#include <memory>
#include <mutex>
#include <string>
#include <cstdint>
#include <array>

namespace pkt
{
	class counter : private noncopyable
	{
		std::string name_;
		std::uint64_t value_;
		std::uint64_t updates_;
	public:
		counter(const char* nm);
	public:
		static std::shared_ptr<counter> of(const char* nm);
	friend class counter_context;
	};

	enum
	{
		counter_pkts,
		counter_bytes,
		counter_invalid,
		counter_ipv4,
		counter_ipv6,
		counter_eth,
		counter_raw,
		counter_null,
		counter_sll,
		counter_tcp,
		counter_udp,
		counter_sctp,
		counter_icmpv4,
		counter_icmpv6,
		counter_ppp,
		counter_pppoe,
		counter_gre,
		counter_vlan,
		counter_vlan_qinq,
		counter_teredo,
		counter_ipv4inipv6,
		counter_ipv6inipv6,
		counter_mpls,

		counter_defrag_ipv4_fragments,
		counter_defrag_ipv4_reassembled,
		counter_defrag_ipv4_timeouts,
		counter_defrag_ipv6_fragments,
		counter_defrag_ipv6_reassembled,
		counter_defrag_ipv6_timeouts,
		counter_defrag_max_hit,

		counter_max
	};

	class counter_context : private noncopyable
	{
		std::array<std::shared_ptr<counter>, counter_max> counters_;
		std::mutex mutex_;
	public:
		counter_context();
	public:
		PKT_INLINE void incr(const int& id);
		PKT_INLINE void add(const int& id, const std::uint64_t& v);
		PKT_INLINE void set(const int& id, const std::uint64_t& v);
		PKT_INLINE std::uint64_t get(const int& id);
		PKT_INLINE const std::string& name(const int& id);
	};
}

#if defined(__PKT_INLINE__)
#include "pkt.counter.inl"
#endif

#endif

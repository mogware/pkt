#ifndef __PKT_ICMPV6__
#define __PKT_ICMPV6__

#include "pkt.decode.h"

namespace pkt
{
	struct ipv6_hdr;
	struct tcp_hdr;
	struct udp_hdr;
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct icmpv6_info
	{
		std::uint16_t  ic_id;
		std::uint16_t  ic_seq;
	});

	PACKED(
	struct icmpv6_hdr
	{
		std::uint8_t  ic_type;
		std::uint8_t  ic_code;
		std::uint16_t ic_csum;

		union {
			icmpv6_info ic_icmpv6i;
			union
			{
				std::uint32_t  ic_unused;
				std::uint32_t  ic_error_ptr;
				std::uint32_t  ic_mtu;
			};
		};

		PKT_INLINE std::uint8_t get_type(void) const;
		PKT_INLINE std::uint8_t get_code(void) const;
		PKT_INLINE std::uint16_t get_csum(void) const;
		PKT_INLINE std::uint32_t get_unused(void) const;
		PKT_INLINE std::uint32_t get_error_ptr(void) const;
		PKT_INLINE std::uint32_t get_mtu(void) const;
	});

	struct icmpv6_vars
	{
		std::uint16_t  id;
		std::uint16_t  seq;
		std::uint32_t  mtu;
		std::uint32_t  error_ptr;

		const ipv6_hdr* emb_ipv6h;
		const tcp_hdr* emb_tcph;
		const udp_hdr* emb_udph;
		const icmpv6_hdr* emb_icmpv6h;

		std::uint32_t emb_ip6_src[4];
		std::uint32_t emb_ip6_dst[4];
		std::uint8_t emb_ip6_proto_next;

		std::uint16_t emb_sport;
		std::uint16_t emb_dport;

		PKT_INLINE icmpv6_vars();
	};

	class icmpv6 : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	private:
		static bool decode_partial_ipv6(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len);
	};
}

#if defined(__PKT_INLINE__)
#include "pkt.icmpv6.inl"
#endif

#endif

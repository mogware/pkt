#ifndef __PKT_ICMPV4__
#define __PKT_ICMPV4__

#include "pkt.decode.h"

namespace pkt
{
	struct ipv4_hdr;
	struct tcp_hdr;
	struct udp_hdr;
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct icmpv4_hdr
	{
		std::uint8_t ic_type;
		std::uint8_t ic_code;
		std::uint16_t ic_checksum;

		PKT_INLINE std::uint8_t get_type(void) const;
		PKT_INLINE std::uint8_t get_code(void) const;
		PKT_INLINE std::uint16_t get_checksum(void) const;
	});

	PACKED(
	struct icmpv4_ext_hdr
	{
		std::uint8_t ic_type;
		std::uint8_t ic_code;
		std::uint16_t ic_checksum;
		std::uint16_t ic_id;
		std::uint16_t ic_seq;
	});

	struct icmpv4_vars
	{
		std::uint16_t id;
		std::uint16_t seq;

		const ipv4_hdr* emb_ipv4h;
		const tcp_hdr* emb_tcph;
		const udp_hdr* emb_udph;
		const icmpv4_hdr* emb_icmpv4h;

		struct ::in_addr emb_ip4_src;
		struct ::in_addr emb_ip4_dst;
		std::uint8_t emb_ip4_hlen;
		std::uint8_t emb_ip4_proto;

		std::uint16_t emb_sport;
		std::uint16_t emb_dport;

		PKT_INLINE icmpv4_vars();
	};

	class icmpv4 : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	private:
		static bool decode_partial_ipv4(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len);
	};
}

#if defined(__PKT_INLINE__)
#include "pkt.icmpv4.inl"
#endif

#endif




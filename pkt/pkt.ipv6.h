#ifndef __PKT_IPV6__
#define __PKT_IPV6__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct ipv6_hdr
	{
		union {
			struct {
				std::uint32_t ip6_flow;
				std::uint16_t ip6_plen;
				std::uint8_t  ip6_nxt;
				std::uint8_t  ip6_hlim;
			};
			std::uint8_t ip6_vfc;
		};
		union {
			struct {
				std::uint32_t ip6_src[4];
				std::uint32_t ip6_dst[4];
			};
			std::uint16_t ip6_addrs[16];
		};

		PKT_INLINE std::uint8_t get_ver(void) const;
		PKT_INLINE std::uint32_t get_class(void) const;
		PKT_INLINE std::uint32_t get_flow(void) const;
		PKT_INLINE std::uint8_t get_nh(void) const;
		PKT_INLINE std::uint16_t get_plen(void) const;
		PKT_INLINE std::uint8_t get_hlim(void) const;
	});

	PACKED(
	struct ipv6_frag_hdr
	{
		std::uint8_t  ip6fh_nxt;
		std::uint8_t  ip6fh_reserved;
		std::uint16_t ip6fh_offlg;
		std::uint32_t ip6fh_ident;
	});


	PACKED(
	struct ipv6_auth_hdr
	{
		std::uint8_t ip6ah_nxt;
		std::uint8_t ip6ah_len;
		std::uint16_t ip6ah_reserved;
		std::uint32_t ip6ah_spi;
		std::uint32_t ip6ah_seq;
	});

	PACKED(
	struct ipv6_esp_hdr
	{
		std::uint32_t ip6esph_spi;
		std::uint32_t ip6esph_seq;
	});

	PACKED(
	struct ipv6_route_hdr
	{
		uint8_t ip6rh_nxt;
		uint8_t ip6rh_len;
		uint8_t ip6rh_type;
		uint8_t ip6rh_segsleft;
	});

	struct ipv6_vars
	{
		uint8_t ip_opts_len;
		uint8_t l4proto;
	};

	struct ipv6_opt_hao
	{
		std::uint8_t ip6hao_type;
		std::uint8_t ip6hao_len;
		struct ::in6_addr ip6hao_hoa;
	};

	struct ipv6_opt_ra
	{
		std::uint8_t ip6ra_type;
		std::uint8_t ip6ra_len;
		std::uint16_t ip6ra_value;
	};

	struct ipv6_opt_jumbo
	{
		std::uint8_t ip6j_type;
		std::uint8_t ip6j_len;
		std::uint32_t ip6j_payload_len;
	};

	struct ipv6_ext_hdrs
	{
		bool rh_set;
		std::uint8_t rh_type;

		bool fh_set;
		bool fh_more_frags_set;
		std::uint8_t fh_nh;

		std::uint8_t fh_prev_nh;
		std::uint16_t fh_prev_hdr_offset;

		std::uint16_t fh_header_offset;
		std::uint16_t fh_data_offset;
		std::uint16_t fh_data_len;

		std::uint16_t fh_offset;
		std::uint32_t fh_id;

		PKT_INLINE std::uint8_t get_nh(void) const;
		PKT_INLINE std::uint16_t get_offset(void) const;
		PKT_INLINE bool get_flag(void) const;
		PKT_INLINE std::uint32_t get_id(void) const;
	};

	class ipv6 : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	private:
		static bool decode_packet(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len);
		static bool decode_ipv4_in_ipv6(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len);
		static bool decode_ipv6_in_ipv6(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len);
		static bool decode_ipv6_ext_hdrs(
			const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
		static void decode_ipv6_frag_header(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const std::uint16_t& hdrextlen,
			const int& len, const std::uint16_t& prev_hdrextlen);
	};
}

#if defined(__PKT_INLINE__)
#include "pkt.ipv6.inl"
#endif

#endif


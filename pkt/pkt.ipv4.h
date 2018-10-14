#ifndef __PKT_IPV4__
#define __PKT_IPV4__

#include <cstring>

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct ipv4_hdr
	{
		std::uint8_t ip_verhl;
		std::uint8_t ip_tos;
		std::uint16_t ip_len;
		std::uint16_t ip_id;
		std::uint16_t ip_off;
		std::uint8_t ip_ttl;
		std::uint8_t ip_proto;
		std::uint16_t ip_csum;
		union
		{
			struct
			{
				struct ::in_addr ip_src;
				struct ::in_addr ip_dst;
			};
			uint16_t ip_addrs[4];
		};

		PKT_INLINE std::uint8_t get_ver(void) const;
		PKT_INLINE std::uint8_t get_hlen(void) const;
		PKT_INLINE std::uint8_t get_iptos(void) const;
		PKT_INLINE std::uint16_t get_iplen(void) const;
		PKT_INLINE std::uint16_t get_ipid(void) const;
		PKT_INLINE std::uint16_t get_ipoffset(void) const;
		PKT_INLINE std::uint8_t get_ipttl(void) const;
		PKT_INLINE std::uint8_t get_ipproto(void) const;
		PKT_INLINE struct ::in_addr get_ipsrc(void) const;
		PKT_INLINE struct ::in_addr get_ipdst(void) const;
	});

	struct ipv4_opt
	{
		std::uint8_t type;
		std::uint8_t len;
		const std::uint8_t* data;

		PKT_INLINE ipv4_opt();
	};

	struct ipv4_options
	{
		ipv4_opt o_rr;
		ipv4_opt o_qs;
		ipv4_opt o_ts;
		ipv4_opt o_sec;
		ipv4_opt o_lsrr;
		ipv4_opt o_cipso;
		ipv4_opt o_sid;
		ipv4_opt o_ssrr;
		ipv4_opt o_rtralt;

		PKT_INLINE ipv4_options();
	};

	enum
	{
		ipv4_opt_flag_eol = 0,
		ipv4_opt_flag_nop,
		ipv4_opt_flag_rr,
		ipv4_opt_flag_ts,
		ipv4_opt_flag_qs,
		ipv4_opt_flag_lsrr,
		ipv4_opt_flag_ssrr,
		ipv4_opt_flag_sid,
		ipv4_opt_flag_sec,
		ipv4_opt_flag_cipso,
		ipv4_opt_flag_rtralt
	};

	struct ipv4_vars
	{
		std::int32_t comp_csum;
		std::uint16_t opt_cnt;
		std::uint16_t opts_set;

		PKT_INLINE ipv4_vars();
	};

	class ipv4 : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	private:
		static bool decode_packet(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len);
		static bool decode_options(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len);
		static bool validate_generic(const std::shared_ptr<packet>& p,
			const ipv4_opt& opt);
		static bool validate_route(const std::shared_ptr<packet>& p,
			const ipv4_opt& opt);
		static bool validate_timestamp(const std::shared_ptr<packet>& p,
			const ipv4_opt& opt);
		static bool validate_cipso(const std::shared_ptr<packet>& p,
			const ipv4_opt& opt);
	};
}

#if defined(__PKT_INLINE__)
#include "pkt.ipv4.inl"
#endif

#endif

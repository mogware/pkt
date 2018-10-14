#ifndef __PKT_TCP__
#define __PKT_TCP__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct tcp_hdr
	{
		std::uint16_t th_sport;
		std::uint16_t th_dport;
		std::uint32_t th_seq;
		std::uint32_t th_ack;
		std::uint8_t th_offx2;
		std::uint8_t th_flags;
		std::uint16_t th_win;
		std::uint16_t th_sum;
		std::uint16_t th_urp;

		std::uint8_t get_offset(void) const
		{
			return (th_offx2 & 0xf0) >> 4;
		}

		std::uint16_t get_src_port(void) const
		{
			return ::ntohs(th_sport);
		}

		std::uint16_t get_dst_port(void) const
		{
			return ::ntohs(th_dport);
		}

		std::uint32_t get_seq(void) const
		{
			return ::ntohl(th_seq);
		}

		std::uint32_t get_ack(void) const
		{
			return ::ntohl(th_ack);
		}

		std::uint16_t get_window(void) const
		{
			return ::ntohs(th_win);
		}

		std::uint16_t get_sum(void) const
		{
			return ::ntohs(th_sum);
		}

		std::uint16_t get_urp(void) const
		{
			return ::ntohs(th_urp);
		}

		bool isset_flag_fin(void) const
		{
			return (th_flags & 0x01) != 0;
		}

		bool isset_flag_syn(void) const
		{
			return (th_flags & 0x02) != 0;
		}

		bool isset_flag_rst(void) const
		{
			return (th_flags & 0x04) != 0;
		}

		bool isset_flag_push(void) const
		{
			return (th_flags & 0x08) != 0;
		}

		bool isset_flag_ack(void) const
		{
			return (th_flags & 0x10) != 0;
		}

		bool isset_flag_urg(void) const
		{
			return (th_flags & 0x20) != 0;
		}
	});

	struct tcp_opt
	{
		std::uint8_t type;
		std::uint8_t len;
		const std::uint8_t* data;

		tcp_opt()
		{
			std::memset(this, 0, sizeof(tcp_opt));
		}
	};

	struct tcp_vars
	{
		bool ts_set;
		std::uint32_t ts_val;
		std::uint32_t ts_ecr;
		tcp_opt sack;
		tcp_opt sackok;
		tcp_opt ws;
		tcp_opt mss;

		tcp_vars()
		{
			std::memset(this, 0, sizeof(tcp_vars));
		}
	};

	class tcp : public decode
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
		static void set_opts(tcp_opt& dst, const tcp_opt& src);
	};
}

#endif


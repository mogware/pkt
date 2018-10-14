#ifndef __PKT_UDP__
#define __PKT_UDP__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct udp_hdr
	{
		std::uint16_t uh_sport;
		std::uint16_t uh_dport;
		std::uint16_t uh_len;
		std::uint16_t uh_sum;

		std::uint16_t get_len(void) const
		{
			return ::ntohs(uh_len);
		}

		std::uint16_t get_src_port(void) const
		{
			return ::ntohs(uh_sport);
		}

		std::uint16_t get_dst_port(void) const
		{
			return ::ntohs(uh_dport);
		}

		std::uint16_t get_sum(void) const
		{
			return ::ntohs(uh_sum);
		}
	});

	class udp : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	private:
		static bool decode_packet(const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len);
	};
}

#endif

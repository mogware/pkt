#ifndef __PKT_SCTP__
#define __PKT_SCTP__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct sctp_hdr
	{
		std::uint16_t sh_sport;
		std::uint16_t sh_dport;
		std::uint32_t sh_vtag;
		std::uint32_t sh_sum;

		std::uint16_t get_src_port(void) const
		{
			return ::ntohs(sh_sport);
		}

		std::uint16_t get_dst_port(void) const
		{
			return ::ntohs(sh_dport);
		}

		std::uint32_t get_vtag(void) const
		{
			return ::ntohl(sh_vtag);
		}

		std::uint32_t get_sum(void) const
		{
			return ::ntohl(sh_sum);
		}
	});

	class sctp : public decode
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


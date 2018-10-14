#ifndef __PKT_SLL__
#define __PKT_SLL__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct sll_hdr
	{
		std::uint16_t sll_pkttype;
		std::uint16_t sll_hatype;
		std::uint16_t sll_halen;
		std::uint8_t sll_addr[8];
		std::uint16_t sll_protocol;

		std::uint16_t get_proto(void) const
		{
			return ::ntohs(sll_protocol);
		}
	});

	class sll : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	};
}

#endif

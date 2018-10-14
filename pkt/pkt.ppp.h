#ifndef __PKT_PPP__
#define __PKT_PPP__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct ppp_hdr
	{
		uint8_t address;
		uint8_t control;
		uint16_t protocol;

		std::uint16_t get_proto(void) const
		{
			return ::ntohs(protocol);
		}
	});

	class ppp : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	};
}

#endif


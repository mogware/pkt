#ifndef __PKT_ETHERNET__
#define __PKT_ETHERNET__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct ethernet_hdr
	{
		std::uint8_t eth_dst[6];
		std::uint8_t eth_src[6];
		std::uint16_t eth_type;
	});

	struct ethernet : public decode
	{
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	};
}

#endif

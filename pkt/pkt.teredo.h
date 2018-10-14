#ifndef __PKT_TEREDO__
#define __PKT_TEREDO__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	class teredo : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
		static void enable(const bool& enabled);
	};
}

#endif


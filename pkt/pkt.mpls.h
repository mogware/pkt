#ifndef __PKT_MPLS__
#define __PKT_MPLS__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	class mpls : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	private:
		static std::uint32_t label(std::uint32_t shim);
		static bool bottom(std::uint32_t shim);
	};
}

#endif

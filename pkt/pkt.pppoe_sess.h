#ifndef __PKT_PPPOE_SESS__
#define __PKT_PPPOE_SESS__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct pppoe_sess_hdr
	{
		std::uint8_t vertypve;
		std::uint8_t code;
		std::uint16_t id;
		std::uint16_t len;
		std::uint16_t protocol;

		std::uint16_t get_len(void) const
		{
			return ::ntohs(len);
		}

		std::uint16_t get_proto(void) const
		{
			return ::ntohs(protocol);
		}
	});

	class pppoe_sess : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	};
}

#endif

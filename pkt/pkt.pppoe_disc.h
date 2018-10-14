#ifndef __PKT_PPPOE_DISC__
#define __PKT_PPPOE_DISC__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct pppoe_disc_hdr
	{
		std::uint8_t vertyp;
		std::uint8_t code;
		std::uint16_t id;
		std::uint16_t len;

		std::uint8_t get_code(void) const
		{
			return code;
		}

		std::uint16_t get_len(void) const
		{
			return ::ntohs(len);
		}
	});

	PACKED(
	struct pppoe_disc_tag
	{
		std::uint16_t type;
		std::uint16_t len;

		std::uint16_t get_type(void) const
		{
			return ::ntohs(type);
		}

		std::uint16_t get_len(void) const
		{
			return ::ntohs(len);
		}
	});

	class pppoe_disc : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	};
}

#endif

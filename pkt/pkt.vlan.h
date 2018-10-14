#ifndef __PKT_VLAN__
#define __PKT_VLAN__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct vlan_hdr
	{
		std::uint16_t vlan_cfi;
		std::uint16_t protocol;

		std::uint8_t get_priority(void) const
		{
			return (::ntohs(vlan_cfi) & 0xE000) >> 13;
		}

		std::uint8_t get_cfi(void) const
		{
			return (::ntohs(vlan_cfi) & 0x0100) >> 12;
		}

		std::uint16_t get_id(void) const
		{
			return ::ntohs(vlan_cfi) & 0x0FFF;
		}

		std::uint16_t get_proto(void) const
		{
			return ::ntohs(protocol);
		}
	});

	class vlan : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	};
}

#endif

#include "pkt.packet.h"
#include "pkt.null.h"
#include "pkt.ipv4.h"
#include "pkt.ipv6.h"
#include "pkt.thread_vars.h"

static const std::uint16_t hdr_size = 4;

bool pkt::null::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_null);

	if (len < hdr_size) {
		p->set_error(null_pkt_too_small);
		return false;
	}

	std::uint32_t type = *(reinterpret_cast<std::uint32_t *>
		(const_cast<std::uint8_t *>(pkt)));
	switch (type) {
	case AF_INET:
		return ipv4::decode(tv, p, p->get_pkt_data() + hdr_size,
				p->get_pkt_len() - hdr_size, pq);
	case AF_INET6:
		return ipv6::decode(tv, p, p->get_pkt_data() + hdr_size,
				p->get_pkt_len() - hdr_size, pq);
	default:
		p->set_error(null_unsupported_type);
		break;
	}
	return true;
}

#include "pkt.packet.h"
#include "pkt.raw.h"
#include "pkt.thread_vars.h"

bool pkt::raw::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_raw);

	if (len < ipv4_header_len) {
		p->set_error(ipv4_pkt_too_small);
		return false;
	}

	if (ip_get_raw_ver(pkt) == 4)
		return ipv4::decode(tv, p, p->get_pkt_data(), p->get_pkt_len(), pq);
	else if (ip_get_raw_ver(pkt) == 6)
		return ipv6::decode(tv, p, p->get_pkt_data(), p->get_pkt_len(), pq);
	else {
		p->set_error(raw_invalid_ipv);
		return false;
	}
	return true;
}

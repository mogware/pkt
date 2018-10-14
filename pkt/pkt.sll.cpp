#include "pkt.packet.h"
#include "pkt.sll.h"
#include "pkt.ipv4.h"
#include "pkt.ipv6.h"
#include "pkt.vlan.h"
#include "pkt.thread_vars.h"

bool pkt::sll::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_sll);

	if (len < sll_header_len) {
		p->set_error(sll_pkt_too_small);
		return false;
	}

	sll_hdr* sllh = reinterpret_cast<sll_hdr *>(const_cast<uint8_t *>(pkt));
	if (sllh == nullptr)
		return false;

	switch (sllh->get_proto()) {
	case ethernet_type_ip:
		return ipv4::decode(tv, p, pkt + sll_header_len,
			len - sll_header_len, pq);
	case ethernet_type_ipv6:
		return ipv6::decode(tv, p, pkt + sll_header_len,
			len - sll_header_len, pq);
	case ethernet_type_vlan:
		return vlan::decode(tv, p, pkt + sll_header_len,
			len - sll_header_len, pq);
	default:
		p->set_error(sll_unsupported_proto);
	}

	return true;
}

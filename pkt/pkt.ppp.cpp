#include "pkt.packet.h"
#include "pkt.ppp.h"
#include "pkt.ipv4.h"
#include "pkt.ipv6.h"
#include "pkt.thread_vars.h"

bool pkt::ppp::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_ppp);

	if (len < ppp_header_len) {
		p->set_error(ppp_pkt_too_small);
		return false;
	}

	p->ppph = reinterpret_cast<ppp_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->ppph == nullptr)
		return false;

	switch (p->ppph->get_proto())
	{
	case ppp_vj_ucomp:
	{
		if (len < (ppp_header_len + ipv4_header_len)) {
			p->set_error(pppvju_pkt_too_small);
			return false;
		}

		ipv4_hdr* icmp4_ip4h = reinterpret_cast<ipv4_hdr *>
			(const_cast<uint8_t *>(pkt + ppp_header_len));

		if (icmp4_ip4h->get_ver() == 4)
			return ipv4::decode(tv, p, pkt + ppp_header_len,
				len - ppp_header_len, pq);
		break;
	}
	case ppp_ip:
		if (len < (ppp_header_len + ipv4_header_len)) {
			p->set_error(pppipv4_pkt_too_small);
			return false;
		}

		return ipv4::decode(tv, p, pkt + ppp_header_len,
			len - ppp_header_len, pq);

	case ppp_ipv6:
		if (len < (ppp_header_len + ipv6_header_len)) {
			p->set_error(pppipv6_pkt_too_small);
			return false;
		}

		return ipv6::decode(tv, p, pkt + ppp_header_len,
			len - ppp_header_len, pq);

	default:
		p->set_error(ppp_unsupported_proto);
	}

	return true;
}

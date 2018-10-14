#include "pkt.packet.h"
#include "pkt.pppoe_sess.h"
#include "pkt.ipv4.h"
#include "pkt.ipv6.h"
#include "pkt.thread_vars.h"

bool pkt::pppoe_sess::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_pppoe);

	if (len < pppoe_sess_header_len) {
		p->set_error(pppoe_pkt_too_small);
		return false;
	}

	p->pppoesh = reinterpret_cast<pppoe_sess_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->pppoesh == nullptr)
		return false;

	if (p->pppoesh->get_len() > 0) {
		switch (p->pppoesh->get_proto())
		{
		case ppp_vj_ucomp:
		{
			if (len < (pppoe_sess_header_len + ipv4_header_len)) {
				p->set_error(pppvju_pkt_too_small);
				return false;
			}

			ipv4_hdr* icmp4_ip4h = reinterpret_cast<ipv4_hdr *>
				(const_cast<uint8_t *>(pkt + pppoe_sess_header_len));

			if (icmp4_ip4h->get_ver() == 4)
				return ipv4::decode(tv, p, pkt + pppoe_sess_header_len,
					len - pppoe_sess_header_len, pq);
			break;
		}
		case ppp_ip:
			if (len < (pppoe_sess_header_len + ipv4_header_len)) {
				p->set_error(pppipv4_pkt_too_small);
				return false;
			}

			return ipv4::decode(tv, p, pkt + pppoe_sess_header_len,
				len - pppoe_sess_header_len, pq);

		case ppp_ipv6:
			if (len < (pppoe_sess_header_len + ipv6_header_len)) {
				p->set_error(pppipv6_pkt_too_small);
				return false;
			}

			return ipv6::decode(tv, p, pkt + pppoe_sess_header_len,
				len - pppoe_sess_header_len, pq);

		default:
			p->set_error(ppp_unsupported_proto);
		}
	}

	return true;
}

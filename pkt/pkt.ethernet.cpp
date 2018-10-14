#include "pkt.packet.h"
#include "pkt.ethernet.h"
#include "pkt.ipv4.h"
#include "pkt.ipv6.h"
#include "pkt.pppoe_sess.h"
#include "pkt.pppoe_disc.h"
#include "pkt.vlan.h"
#include "pkt.mpls.h"
#include "pkt.thread_vars.h"

bool pkt::ethernet::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_eth);

	if (len < ethernet_header_len)
	{
		p->set_error(ethernet_pkt_too_small);
		return false;
	}

	p->ethh = reinterpret_cast<ethernet_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->ethh == nullptr)
		return false;

	switch (::ntohs(p->ethh->eth_type))
	{
	case ethernet_type_ip:
		return ipv4::decode(tv, p, pkt + ethernet_header_len,
				len - ethernet_header_len, pq);
	case ethernet_type_ipv6:
		return ipv6::decode(tv, p, pkt + ethernet_header_len,
			len - ethernet_header_len, pq);
	case ethernet_type_pppoe_sess:
		return pppoe_sess::decode(tv, p, pkt + ethernet_header_len,
			len - ethernet_header_len, pq);
	case ethernet_type_pppoe_disc:
		return pppoe_disc::decode(tv, p, pkt + ethernet_header_len,
			len - ethernet_header_len, pq);
	case ethernet_type_vlan:
	case ethernet_type_8021qinq:
		return vlan::decode(tv, p, pkt + ethernet_header_len,
			len - ethernet_header_len, pq);
	case ethernet_type_mpls_unicast:
	case ethernet_type_mpls_multicast:
		return mpls::decode(tv, p, pkt + ethernet_header_len,
			len - ethernet_header_len, pq);
	case ethernet_type_dce:
		if (len < ethernet_dce_header_len)
			p->set_error(dce_pkt_too_small);
		else
			return ethernet::decode(tv, p, pkt + ethernet_dce_header_len,
					len - ethernet_dce_header_len, pq);
		break;
	}

	return true;
}

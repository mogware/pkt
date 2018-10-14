#include "pkt.packet.h"
#include "pkt.vlan.h"
#include "pkt.ipv4.h"
#include "pkt.ipv6.h"
#include "pkt.pppoe_sess.h"
#include "pkt.pppoe_disc.h"
#include "pkt.thread_vars.h"

bool pkt::vlan::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	if (p->vlan_idx == 0)
		tv->cc.incr(counter_vlan);
	else if (p->vlan_idx == 1)
		tv->cc.incr(counter_vlan_qinq);

	if (len < vlan_header_len) {
		p->set_error(vlan_header_too_small);
		return false;
	}

	if (p->vlan_idx >= 2) {
		p->set_error(vlan_header_too_many_layers);
		return false;
	}

	p->vlanh[p->vlan_idx] = reinterpret_cast<vlan_hdr *>
			(const_cast<uint8_t *>(pkt));
	if (p->vlanh[p->vlan_idx] == nullptr)
		return false;

	p->vlan_id[p->vlan_idx] = p->vlanh[p->vlan_idx]->get_id();
	p->vlan_idx++;

	switch (p->vlanh[p->vlan_idx]->get_proto()) {
	case ethernet_type_ip:
		return ipv4::decode(tv, p, pkt + vlan_header_len,
			len - vlan_header_len, pq);
	case ethernet_type_ipv6:
		return ipv6::decode(tv, p, pkt + vlan_header_len,
			len - vlan_header_len, pq);
	case ethernet_type_pppoe_sess:
		return pppoe_sess::decode(tv, p, pkt + vlan_header_len,
			len - vlan_header_len, pq);
	case ethernet_type_pppoe_disc:
		return pppoe_disc::decode(tv, p, pkt + vlan_header_len,
			len - vlan_header_len, pq);
	case ethernet_type_vlan:
	case ethernet_type_8021ad:
		if (p->vlan_idx >= 2)
			p->set_error(vlan_header_too_many_layers);
		else
			return vlan::decode(tv, p, pkt + vlan_header_len,
				len - vlan_header_len, pq);
		break;
	default:
		p->set_error(vlan_unknown_type);
		break;
	}

	return true;
}

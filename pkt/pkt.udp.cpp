#include "pkt.packet.h"
#include "pkt.udp.h"
#include "pkt.teredo.h"
#include "pkt.thread_vars.h"

bool pkt::udp::decode_packet(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	if (len < udp_header_len) {
		p->set_error(udp_pkt_too_small);
		return false;
	}

	p->udph = reinterpret_cast<udp_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->udph == nullptr)
		return false;

	if (len != p->udp_get_len()) {
		p->set_error(udp_len_invalid);
		return false;
	}

	p->sport = p->udp_get_src_port();
	p->dport = p->udp_get_dst_port();

	p->proto = IPPROTO_UDP;

	p->payload = pkt + udp_header_len;
	p->payload_len = len - udp_header_len;

	return true;
}

bool pkt::udp::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_udp);

	if (! decode_packet(p, pkt, len)) {
		p->udph = nullptr;
		return false;
	}

	if (teredo::decode(tv, p, p->payload, p->payload_len, pq)) {
		// p->flow_setup_packet();
		return true;
	}

	// p->flow_setup_packet();

	return true;
}

#include "pkt.packet.h"
#include "pkt.mpls.h"
#include "pkt.ethernet.h"
#include "pkt.ipv4.h"
#include "pkt.ipv6.h"
#include "pkt.thread_vars.h"

static const std::uint32_t mpls_max_reserved_label = 15;
static const std::uint16_t mpls_pw_len = 4;

std::uint32_t pkt::mpls::label(std::uint32_t shim)
{
	return ::ntohl(shim) >> 12;
}

bool pkt::mpls::bottom(std::uint32_t shim)
{
	return ((::ntohl(shim) >> 8) & 0x1) != 0;
}

bool pkt::mpls::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	int plen = len;

	tv->cc.incr(counter_mpls);

	std::uint32_t shim;
	do {
		if (plen < mpls_header_len) {
			p->set_error(mpls_header_too_small);
			return false;
		}
		shim = *(uint32_t *)pkt;
		pkt += mpls_header_len;
		plen -= mpls_header_len;
	} while (!bottom(shim));

	switch (label(shim)) {
	case 0:	// IPV4
		return ipv4::decode(tv, p, pkt, plen, pq);

	case 1:	// ROUTER_ALERT
		p->set_error(mpls_bad_label_router_alert);
		return false;

	case 2:	// IPV6
		return ipv6::decode(tv, p, pkt, plen, pq);

	case 3:	// NULL
		p->set_error(mpls_bad_label_implicit_null);
		return false;
	}

	if (label(shim) < mpls_max_reserved_label) {
		p->set_error(mpls_bad_label_reserved);
		return false;
	}

	switch (pkt[0] >> 4) {
	case 4: // PROTO_IPV4:
		return ipv4::decode(tv, p, pkt, plen, pq);
	case 6: // PROTO_IPV6:
		return ipv6::decode(tv, p, pkt, plen, pq);
	case 0: // PROTO_ETHERNET_PW:
		return ethernet::decode(tv, p, pkt + mpls_pw_len,
			plen - mpls_pw_len, pq);
	default:
		p->set_error(mpls_unknown_payload_type);
		return false;
	}
	return true;
}

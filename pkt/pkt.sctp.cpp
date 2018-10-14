#include "pkt.packet.h"
#include "pkt.sctp.h"
#include "pkt.thread_vars.h"

bool pkt::sctp::decode_packet(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	if (len < sctp_header_len) {
		p->set_error(sctp_pkt_too_small);
		return false;
	}

	p->sctph = reinterpret_cast<sctp_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->sctph == nullptr)
		return false;

	p->sport = p->sctp_get_src_port();
	p->dport = p->sctp_get_dst_port();

	p->proto = IPPROTO_SCTP;

	return true;
}

bool pkt::sctp::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_sctp);

	if (!decode_packet(p, pkt, len)) {
		p->sctph = nullptr;
		return false;
	}

	// p->flow_setup_packet();

	return true;
}

#include "pkt.packet.h"
#include "pkt.teredo.h"

static const std::uint16_t teredo_orig_indication_length = 8;
static bool g_teredo_enabled = true;

void pkt::teredo::enable(const bool& enabled)
{
	g_teredo_enabled = enabled;
}

bool pkt::teredo::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	if (!g_teredo_enabled)
		return false;

	if (len < ipv6_header_len)
		return false;

	const std::uint8_t* start = pkt;
	if (start[0] == 0x0) {
		switch (start[1]) {
		case 0x0:
			if (len >= teredo_orig_indication_length + ipv6_header_len)
				start += teredo_orig_indication_length;
			else
				return false;
			break;
		case 0x1:
			return false;
		default:
			return false;
		}
	}

	if (ip_get_raw_ver(start) == 6) {
		ipv6_hdr* thdr = reinterpret_cast<ipv6_hdr *>(const_cast<uint8_t *>(pkt));
		if (thdr == nullptr)
			return false;
		if (len == ipv6_header_len + thdr->get_plen() + (start - pkt)) {
/*
			if (pq != NULL) {
				int blen = len - (start - pkt);
				Packet *tp = PacketTunnelPktSetup(tv, dtv, p, start, blen,
					DECODE_TUNNEL_IPV6, pq);
				if (tp != nullptr) {
					PKT_SET_SRC(tp, PKT_SRC_DECODER_TEREDO);
					PacketEnqueue(pq, tp);
					StatsIncr(tv, dtv->counter_teredo);
					return true;
				}
			}
*/
		}
		return false;
	}

	return false;
}

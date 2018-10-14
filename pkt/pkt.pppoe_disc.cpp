#include "pkt.packet.h"
#include "pkt.pppoe_disc.h"
#include "pkt.thread_vars.h"

bool pkt::pppoe_disc::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_pppoe);

	if (len < pppoe_disc_header_min_len) {
		p->set_error(pppoe_pkt_too_small);
		return false;
	}

	p->pppoedh = reinterpret_cast<pppoe_disc_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->pppoedh == nullptr)
		return false;

	switch (p->pppoedh->get_code())
	{
	case 0x09: // PPPOE_CODE_PADI
	case 0x07: // PPPOE_CODE_PADO
	case 0x19: // PPPOE_CODE_PADR
	case 0x65: // PPPOE_CODE_PADS
	case 0xa7: // PPPOE_CODE_PADT
		break;
	default:
		p->set_error(pppoe_wrong_code);
		return false;
	}

	std::uint16_t pppoe_length = p->pppoedh->get_len();
	std::uint16_t packet_length = len - pppoe_disc_header_min_len;

	std::uint16_t disc_len = pppoe_disc_header_min_len;
	pppoe_disc_tag* pppoedt = reinterpret_cast<pppoe_disc_tag *>
		(const_cast<uint8_t *>(pkt + disc_len));

	pppoe_disc_tag* pppoend = reinterpret_cast<pppoe_disc_tag *>
		(const_cast<uint8_t *>(pkt + (len - sizeof(pppoe_disc_tag))));

	while (pppoe_length >= 4 && packet_length >= 4 && pppoedt < pppoend) {
		std::uint16_t tag_length = pppoedt->get_len();

		if (pppoe_length >= (4 + tag_length))
			pppoe_length -= (4 + tag_length);
		else
			pppoe_length = 0;

		if (packet_length >= 4 + tag_length)
			packet_length -= (4 + tag_length);
		else
			packet_length = 0;

		disc_len += (4 + tag_length);
		pppoedt = reinterpret_cast<pppoe_disc_tag *>
				(const_cast<uint8_t *>(pkt + disc_len));
	}

	return true;
}

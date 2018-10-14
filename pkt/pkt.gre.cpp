#include "pkt.packet.h"
#include "pkt.gre.h"
#include "pkt.thread_vars.h"

static const std::uint16_t gre_version_0 = 0x0000;
static const std::uint16_t gre_version_1 = 0x0001;

bool pkt::gre::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)

{
	tv->cc.incr(counter_gre);

	if (len < gre_header_len)
	{
		p->set_error(gre_pkt_too_small);
		return false;
	}

	p->greh = reinterpret_cast<gre_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->greh == nullptr)
		return false;

	switch (p->gre_get_ver())
	{
	case gre_version_0:
	{
		if (p->gre_flag_isset_recur())
		{
			p->set_error(gre_version0_recur);
			return false;
		}

		if (p->grev1_flag_isset_flags())
		{
			p->set_error(gre_version0_flags);
			return false;
		}

		std::uint16_t header_len = gre_header_len;

		if (p->gre_flag_isset_ky())
			header_len += gre_key_len;

		if (p->gre_flag_isset_sq())
			header_len += gre_seq_len;

		if (p->gre_flag_isset_chksum() || p->gre_flag_isset_route())
			header_len += gre_chksum_len + gre_offset_len;

		if (header_len > len)
		{
			p->set_error(gre_version0_hdr_too_big);
			return false;
		}

		if (p->gre_flag_isset_route())
		{
			while (true)
			{
				if ((header_len + gre_sre_hdr_len) > len)
				{
					p->set_error(gre_version0_malformed_sre_hdr);
					return false;
				}

				gre_sre_hdr* gsre =
					reinterpret_cast<gre_sre_hdr *>(const_cast<uint8_t *>(pkt));
				header_len += gre_sre_hdr_len;

				if (::ntohs(gsre->af) == 0 && gsre->sre_length == 0)
					break;

				header_len += gsre->sre_length;
				if (header_len > len)
				{
					p->set_error(gre_version0_malformed_sre_hdr);
					return false;
				}
			}
		}
		break;
	}

	case gre_version_1:
	{
		if (p->gre_flag_isset_chksum())
		{
			p->set_error(gre_version1_chksum);
			return false;
		}

		if (p->gre_flag_isset_route())
		{
			p->set_error(gre_version1_route);
			return false;
		}

		if (p->gre_flag_isset_ssr())
		{
			p->set_error(gre_version1_ssr);
			return false;
		}

		if (p->gre_flag_isset_recur())
		{
			p->set_error(gre_version1_recur);
			return false;
		}

		if (p->grev1_flag_isset_flags())
		{
			p->set_error(gre_version1_flags);
			return false;
		}

		if (p->gre_get_proto() != ethernet_type_gre_ppp)
		{
			p->set_error(gre_version1_wrong_protocol);
			return false;
		}

		if (!p->gre_flag_isset_ky())
		{
			p->set_error(gre_version1_no_key);
			return false;
		}

		std::uint16_t header_len = gre_header_len + gre_key_len;

		if (p->gre_flag_isset_sq())
			header_len += gre_seq_len;

		if (p->grev1_flag_isset_ack())
			header_len += grev1_ack_len;

		if (header_len > len)
		{
			p->set_error(gre_version1_hdr_too_big);
			return false;
		}

		break;
	}

	default:
		p->set_error(gre_wrong_version);
		return false;
	}

	switch (p->gre_get_proto())
	{
	case ethernet_type_ip:
	case ethernet_type_gre_ppp:
	case ethernet_type_ipv6:
	case ethernet_type_vlan:
	case ethernet_type_erspan:
	case ethernet_type_bridge:
		//TODO
		break;
	}

	return true;
}

#if !defined(__PKT_INLINE__)
#include "pkt.gre.inl"
#endif

#include "pkt.packet.h"
#include "pkt.ipv6.h"
#include "pkt.tcp.h"
#include "pkt.udp.h"
#include "pkt.icmpv6.h"
#include "pkt.sctp.h"
#include "pkt.thread_vars.h"
#include "pkt.packet_queue.h"

const std::uint8_t ipv6opt_pad1 = 0x00;
const std::uint8_t ipv6opt_padn = 0x01;
const std::uint8_t ipv6opt_ra = 0x05;
const std::uint8_t ipv6opt_jumbo = 0xC2;
const std::uint8_t ipv6opt_hao = 0xC9;

bool pkt::ipv6::decode_ipv4_in_ipv6(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	if (len < ipv4_header_len)
	{
		p->set_error(ipv4_in_ipv6_pkt_too_small);
		return false;
	}

	if (ip_get_raw_ver(pkt) != 4)
	{
		p->set_error(ipv4_in_ipv6_wrong_ip_ver);
		return false;
	}

/*TODO
	if (pq != NULL) {
		Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt, plen, DECODE_TUNNEL_IPV4, pq);
		if (tp != NULL) {
			PKT_SET_SRC(tp, PKT_SRC_DECODER_IPV6);
			PacketEnqueue(pq, tp);
			StatsIncr(tv, dtv->counter_ipv4inipv6);
		}
	}
*/
	return true;
}

bool pkt::ipv6::decode_ipv6_in_ipv6(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	if (len < ipv6_header_len)
	{
		p->set_error(ipv6_in_ipv6_pkt_too_small);
		return false;
	}

	if (ip_get_raw_ver(pkt) != 6)
	{
		p->set_error(ipv6_in_ipv6_wrong_ip_ver);
		return false;
	}

	/*TODO
	if (pq != NULL) {
		Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt, plen, DECODE_TUNNEL_IPV6, pq);
		if (tp != NULL) {
			PKT_SET_SRC(tp, PKT_SRC_DECODER_IPV6);
			PacketEnqueue(pq, tp);
			StatsIncr(tv, dtv->counter_ipv6inipv6);
		}
	}
	*/
	return true;
}

void pkt::ipv6::decode_ipv6_frag_header(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const std::uint16_t& hdrextlen,
	const int& len, const std::uint16_t& prev_hdrextlen)
{
	std::uint16_t frag_offset = (*(pkt + 2) << 8 | *(pkt + 3)) & 0xFFF8;
	int frag_morefrags = (*(pkt + 2) << 8 | *(pkt + 3)) & 0x0001;

	p->ipv6eh.fh_offset = frag_offset;
	p->ipv6eh.fh_more_frags_set = frag_morefrags ? true : false;
	p->ipv6eh.fh_nh = *pkt;

	std::uint32_t fh_id;
	std::memcpy(&fh_id, pkt + 4, 4);
	p->ipv6eh.fh_id = ::ntohl(fh_id);

	std::uint16_t frag_hdr_offset = static_cast<std::uint16_t>
		(pkt - p->get_pkt_data());
	std::uint16_t data_offset = static_cast<std::uint16_t>
		(frag_hdr_offset + hdrextlen);
	std::uint16_t data_len = len - hdrextlen;

	p->ipv6eh.fh_header_offset = frag_hdr_offset;
	p->ipv6eh.fh_data_offset = data_offset;
	p->ipv6eh.fh_data_len = data_len;

	if (prev_hdrextlen)
		p->ipv6eh.fh_prev_hdr_offset = frag_hdr_offset - prev_hdrextlen;
}

bool pkt::ipv6::decode_packet(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	if (len < ipv6_header_len)
	{
		p->set_error(ipv6_pkt_too_small);
		return false;
	}

	if (ip_get_raw_ver(pkt) != 6)
	{
		p->set_error(ipv6_wrong_ip_ver);
		return false;
	}

	p->ipv6h = reinterpret_cast<ipv6_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->ipv6h == nullptr)
		return false;

	if (len < ipv6_header_len + p->ipv6_get_plen())
	{
		p->set_error(ipv6_trunc_pkt);
		return false;
	}

	p->set_ipv6_src_addr(&p->src);
	p->set_ipv6_dst_addr(&p->dst);

	return true;
}

bool pkt::ipv6::decode_ipv6_ext_hdrs(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	const std::uint8_t* orig_pkt = pkt;
	std::uint16_t hdrextlen = 0;
	bool exthdr_fh_done = false;
	int dstopts = 0;
	bool hh = false;
	bool rh = false;
	bool eh = false;
	bool ah = false;

	std::uint8_t nh = p->ipv6_get_nh();
	std::uint16_t plen = len;

	while (true)
	{
		if (nh == IPPROTO_NONE && plen > 0)
		{
			p->set_error(ipv6_data_after_none_header);
			return false;
		}

		if (plen < 2)
			return true;

		switch (nh)
		{
		case IPPROTO_TCP:
			p->ipv6vars.l4proto = nh;
			return tcp::decode(tv, p, pkt, plen, pq);

		case IPPROTO_UDP:
			p->ipv6vars.l4proto = nh;
			return udp::decode(tv, p, pkt, plen, pq);

		case IPPROTO_ICMPV6:
			p->ipv6vars.l4proto = nh;
			return icmpv6::decode(tv, p, pkt, plen, pq);

		case IPPROTO_SCTP:
			p->ipv6vars.l4proto = nh;
			return sctp::decode(tv, p, pkt, plen, pq);

		case IPPROTO_ROUTING:
		{
			p->ipv6vars.l4proto = nh;
			hdrextlen = 8 + (*(pkt + 1) * 8);

			if (hdrextlen > plen)
			{
				p->set_error(ipv6_trunc_exthdr);
				return false;
			}

			if (rh)
				p->set_error(ipv6_exthdr_dupl_eh);
			rh = true;

			p->ipv6eh.rh_set = true;

			std::uint8_t ipv6rh_type = *(pkt + 2);
			if (ipv6rh_type == 0)
				p->set_error(ipv6_exthdr_rh_type_0);
			p->ipv6eh.rh_type = ipv6rh_type;

			nh = *pkt;
			pkt += hdrextlen;
			plen -= hdrextlen;

			break;
		}
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		{
			ipv6_opt_hao hao_s, *hao = &hao_s;
			ipv6_opt_ra ra_s, *ra = &ra_s;
			ipv6_opt_jumbo jumbo_s, *jumbo = &jumbo_s;

			p->ipv6vars.l4proto = nh;
			hdrextlen = (*(pkt + 1) + 1) << 3;

			if (hdrextlen > plen)
			{
				p->set_error(ipv6_trunc_exthdr);
				return false;
			}

			const std::uint8_t* ptr = pkt + 2;
			std::uint16_t optslen = 0;

			if (nh == IPPROTO_HOPOPTS)
			{
				if (hh)
					p->set_error(ipv6_exthdr_dupl_hh);
				hh = true;
				optslen = ((*(pkt + 1) + 1) << 3) - 2;
			}
			else if (nh == IPPROTO_DSTOPTS)
			{
				if (dstopts == 0)
				{
					optslen = ((*(pkt + 1) + 1) << 3) - 2;
					dstopts = 1;
				}
				else if (dstopts == 1)
				{
					optslen = ((*(pkt + 1) + 1) << 3) - 2;
					dstopts = 2;
				}
				else
				{
					p->set_error(ipv6_exthdr_dupl_hh);
					nh = *pkt;
					pkt += hdrextlen;
					plen -= hdrextlen;
					break;
				}
			}

			if (optslen > plen)
			{
				p->set_error(ipv6_exthdr_invalid_optlen);
				nh = *pkt;
				pkt += hdrextlen;
				plen -= hdrextlen;
				break;
			}

			std::uint16_t padn_cnt = 0;
			std::uint16_t other_cnt = 0;
			std::uint16_t offset = 0;

			while (offset < optslen)
			{
				if (*ptr == ipv6opt_pad1)
				{
					padn_cnt++;
					offset++;
					ptr++;
					continue;
				}

				if (offset + 1 >= optslen)
				{
					p->set_error(ipv6_exthdr_invalid_optlen);
					break;
				}

				std::uint8_t ip6_optlen = *(ptr + 1);

				if ((offset + 1 + ip6_optlen) > optslen)
				{
					p->set_error(ipv6_exthdr_invalid_optlen);
					break;
				}

				if (*ptr == ipv6opt_padn)
				{
					padn_cnt++;
					if (ip6_optlen == 0)
						p->set_error(ipv6_exthdr_zero_len_padn);
				}
				else if (*ptr == ipv6opt_ra)
				{
					ra->ip6ra_type = *ptr;
					ra->ip6ra_len = ip6_optlen;

					if (ip6_optlen < sizeof(ra->ip6ra_value))
					{
						p->set_error(ipv6_exthdr_invalid_optlen);
						break;
					}

					std::memcpy(&ra->ip6ra_value, (ptr + 2), sizeof(ra->ip6ra_value));
					ra->ip6ra_value = ::ntohs(ra->ip6ra_value);
					other_cnt++;
				}
				else if (*ptr == ipv6opt_jumbo)
				{
					jumbo->ip6j_type = *ptr;
					jumbo->ip6j_len = ip6_optlen;

					if (ip6_optlen < sizeof(jumbo->ip6j_payload_len))
					{
						p->set_error(ipv6_exthdr_invalid_optlen);
						break;
					}

					std::memcpy(&jumbo->ip6j_payload_len, (ptr + 2), sizeof(jumbo->ip6j_payload_len));
					jumbo->ip6j_payload_len = ::ntohl(jumbo->ip6j_payload_len);
				}
				else if (*ptr == ipv6opt_hao)
				{
					hao->ip6hao_type = *ptr;
					hao->ip6hao_len = ip6_optlen;

					if (ip6_optlen < sizeof(hao->ip6hao_hoa))
					{
						p->set_error(ipv6_exthdr_invalid_optlen);
						break;
					}

					std::memcpy(&hao->ip6hao_hoa, (ptr + 2), sizeof(hao->ip6hao_hoa));
					other_cnt++;
				}
				else
				{
					if (nh == IPPROTO_HOPOPTS)
						p->set_error(ipv6_hopopts_unknown_opt);
					else
						p->set_error(ipv6_dstopts_unknown_opt);

					other_cnt++;
				}

				std::uint16_t optlen = (*(ptr + 1) + 2);
				ptr += optlen;
				offset += optlen;
			}

			if (padn_cnt > 0 && other_cnt == 0)
			{
				if (nh == IPPROTO_HOPOPTS)
					p->set_error(ipv6_hopopts_only_padding);
				else
					p->set_error(ipv6_dstopts_only_padding);
			}
			
			nh = *pkt;
			pkt += hdrextlen;
			plen -= hdrextlen;

			break;
		}
		case IPPROTO_FRAGMENT:
		{
			p->ipv6vars.l4proto = nh;

			if (! exthdr_fh_done)
			{
				p->ipv6eh.fh_offset =
					static_cast<std::uint16_t>(pkt - orig_pkt);
				exthdr_fh_done = true;
			}

			std::uint16_t prev_hdrextlen = hdrextlen;
			hdrextlen = sizeof(ipv6_frag_hdr);
			if (hdrextlen > plen)
			{
				p->set_error(ipv6_trunc_exthdr);
				return false;
			}

			if (*(pkt + 1) != 0)
				p->set_error(ipv6_fh_non_zero_res_field);

			if (p->ipv6eh.fh_set)
				p->set_error(ipv6_exthdr_dupl_fh);
			p->ipv6eh.fh_set = true;

			decode_ipv6_frag_header(p, pkt, hdrextlen, plen, prev_hdrextlen);

			if (p->ipv6eh.fh_more_frags_set == 0 && p->ipv6eh.fh_offset == 0)
			{
				p->set_error(ipv6_exthdr_useless_fh);

				nh = *pkt;
				pkt += hdrextlen;
				plen -= hdrextlen;
				break;
			}

			p->flags |= pkt_is_fragmented;
			return true;
		}
		case IPPROTO_ESP:
			p->ipv6vars.l4proto = nh;
			hdrextlen = sizeof(ipv6_esp_hdr);
			if (hdrextlen > plen)
			{
				p->set_error(ipv6_trunc_exthdr);
				return false;
			}

			if (eh)
				p->set_error(ipv6_exthdr_dupl_eh);
			eh = true;

			nh = *pkt;
			pkt += hdrextlen;
			plen -= hdrextlen;

			break;

		case IPPROTO_AH:
		{
			p->ipv6vars.l4proto = nh;
			hdrextlen = sizeof(ipv6_auth_hdr);
			if (*(pkt + 1) > 0)
				hdrextlen += ((*(pkt + 1) - 1) * 4);

			if (hdrextlen > plen)
			{
				p->set_error(ipv6_trunc_exthdr);
				return false;
			}

			ipv6_auth_hdr* ahhdr = reinterpret_cast<ipv6_auth_hdr *>(
					const_cast<uint8_t *>(pkt));

			if (ahhdr->ip6ah_reserved != 0x0000)
				p->set_error(ipv6_exthdr_ah_res_not_null);

			if (ah)
				p->set_error(ipv6_exthdr_dupl_ah);
			ah = true;

			nh = *pkt;
			pkt += hdrextlen;
			plen -= hdrextlen;

			break;
		}
		case IPPROTO_IPIP:
			p->ipv6vars.l4proto = nh;
			return icmpv6::decode(tv, p, pkt, plen, pq);

		case IPPROTO_NONE:
			p->ipv6vars.l4proto = nh;
			break;

		case IPPROTO_ICMP:
			p->set_error(ipv6_with_icmpv4);
			return false;

		case IPPROTO_MH:
		case IPPROTO_HIP:
		case IPPROTO_SHIM6:
			hdrextlen = 8 + (*(pkt + 1) * 8);
			if (hdrextlen > plen) {
				p->set_error(ipv6_trunc_exthdr);
				return false;
			}

			nh = *pkt;
			pkt += hdrextlen;
			plen -= hdrextlen;
			break;

		default:
			p->ipv6vars.l4proto = nh;
			p->set_error(ipv6_unknown_next_header);
			return false;
		}
	}

	return true;
}

bool pkt::ipv6::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_ipv6);

	if (! decode_packet(p, pkt, len))
	{
		p->ipv6h = nullptr;
		return false;
	}

	switch (p->ipv6_get_nh())
	{
	case IPPROTO_TCP:
		p->ipv6vars.l4proto = IPPROTO_TCP;
		return tcp::decode(tv, p, pkt + ipv6_header_len,
			p->ipv6_get_plen(), pq);
	case IPPROTO_UDP:
		p->ipv6vars.l4proto = IPPROTO_UDP;
		return udp::decode(tv, p, pkt + ipv6_header_len,
			p->ipv6_get_plen(), pq);
	case IPPROTO_ICMPV6:
		p->ipv6vars.l4proto = IPPROTO_ICMPV6;
		return icmpv6::decode(tv, p, pkt + ipv6_header_len,
			p->ipv6_get_plen(), pq);
	case IPPROTO_SCTP:
		p->ipv6vars.l4proto = IPPROTO_SCTP;
		return sctp::decode(tv, p, pkt + ipv6_header_len,
			p->ipv6_get_plen(), pq);
	case IPPROTO_IPIP:
		p->ipv6vars.l4proto = IPPROTO_IPIP;
		return decode_ipv4_in_ipv6(p, pkt + ipv6_header_len,
			p->ipv6_get_plen());
	case IPPROTO_IPV6:
		return decode_ipv6_in_ipv6(p, pkt + ipv6_header_len,
			p->ipv6_get_plen());
	case IPPROTO_FRAGMENT:
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_NONE:
	case IPPROTO_DSTOPTS:
	case IPPROTO_AH:
	case IPPROTO_ESP:
	case IPPROTO_MH:
	case IPPROTO_HIP:
	case IPPROTO_SHIM6:
		decode_ipv6_ext_hdrs(tv, p, pkt + ipv6_header_len,
			p->ipv6_get_plen(), pq);
		break;
	case IPPROTO_ICMP:
		p->set_error(ipv6_with_icmpv4);
		break;
	default:
		p->ipv6vars.l4proto = p->ipv6_get_nh();
		p->set_error(ipv6_unknown_next_header);
		break;
	}
	p->proto = p->ipv6_get_l4proto();

	if (p->ipv6eh.fh_set && pq != nullptr)
	{
		std::shared_ptr<packet> rp = defrag_packet(tv, p, pq);
		if (rp != nullptr)
			pq->enque(rp);
	}

	return true;
}

#if !defined(__PKT_INLINE__)
#include "pkt.ipv6.inl"
#endif
#include "pkt.packet.h"
#include "pkt.ipv4.h"
#include "pkt.tcp.h"
#include "pkt.udp.h"
#include "pkt.gre.h"
#include "pkt.icmpv4.h"
#include "pkt.sctp.h"
#include "pkt.thread_vars.h"
#include "pkt.packet_queue.h"

/* ipv4 option codes */
static const std::uint8_t ipv4_opt_eol = 0x00;
static const std::uint8_t ipv4_opt_nop = 0x01;
static const std::uint8_t ipv4_opt_rr = 0x07;
static const std::uint8_t ipv4_opt_qs = 0x19;
static const std::uint8_t ipv4_opt_ts = 0x44;
static const std::uint8_t ipv4_opt_sec = 0x82;
static const std::uint8_t ipv4_opt_lsrr = 0x83;
static const std::uint8_t ipv4_opt_cipso = 0x86;
static const std::uint8_t ipv4_opt_sid = 0x88;
static const std::uint8_t ipv4_opt_ssrr = 0x89;
static const std::uint8_t ipv4_opt_rtralt = 0x94;

/* ipv4 option lengths (fixed) */
static const std::uint8_t ipv4_opt_sec_len = 11;
static const std::uint8_t ipv4_opt_sid_len = 4;
static const std::uint8_t ipv4_opt_rtralt_len = 4;

/* ipv4 option lengths (variable) */
static const std::uint8_t ipv4_opt_route_min = 3;
static const std::uint8_t ipv4_opt_qs_min = 8;
static const std::uint8_t ipv4_opt_ts_min = 5;
static const std::uint8_t ipv4_opt_cipso_min = 10;

bool pkt::ipv4::validate_generic(
	const std::shared_ptr<packet>& p, const ipv4_opt& opt)
{
	switch (opt.type)
	{
	case ipv4_opt_qs:
		if (opt.len < ipv4_opt_qs_min)
		{
			p->set_error(ipv4_opt_invalid_len);
			return false;
		}
		break;
	case ipv4_opt_sec:
		if (opt.len != ipv4_opt_sec_len)
		{
			p->set_error(ipv4_opt_invalid_len);
			return false;
		}
		break;
	case ipv4_opt_sid:
		if (opt.len != ipv4_opt_sid_len)
		{
			p->set_error(ipv4_opt_invalid_len);
			return false;
		}
		break;
	case ipv4_opt_rtralt:
		if (opt.len != ipv4_opt_rtralt_len)
		{
			p->set_error(ipv4_opt_invalid_len);
			return false;
		}
		break;
	default:
		p->set_error(ipv4_opt_invalid);
		return false;
	}
	return true;
}

bool pkt::ipv4::validate_route(
	const std::shared_ptr<packet>& p, const ipv4_opt& opt)
{
	if (opt.len < ipv4_opt_route_min)
	{
		p->set_error(ipv4_opt_invalid_len);
		return false;
	}

	if (opt.data == NULL)
	{
		p->set_error(ipv4_opt_malformed);
		return false;
	}

	std::uint8_t ptr = *opt.data;
	if ((ptr < 4) || (ptr % 4) || (ptr > opt.len + 1))
	{
		p->set_error(ipv4_opt_malformed);
		return false;
	}

	return true;
}

bool pkt::ipv4::validate_timestamp(
	const std::shared_ptr<packet>& p, const ipv4_opt& opt)
{
	if (opt.len < ipv4_opt_ts_min)
	{
		p->set_error(ipv4_opt_invalid_len);
		return false;
	}

	if (opt.data == NULL)
	{
		p->set_error(ipv4_opt_malformed);
		return false;
	}

	std::uint8_t ptr = *opt.data;
	if (ptr < 5)
	{
		p->set_error(ipv4_opt_malformed);
		return false;
	}

	std::uint8_t flag = *(opt.data + 3) & 0x00ff;
	std::uint8_t size = ((flag == 1) || (flag == 3)) ? 8 : 4;

	if (((ptr - 5) % size) || (ptr > opt.len + 1))
	{
		p->set_error(ipv4_opt_malformed);
		return false;
	}

	return true;
}

bool pkt::ipv4::validate_cipso(
	const std::shared_ptr<packet>& p, const ipv4_opt& opt)
{
	if (opt.len < ipv4_opt_cipso_min)
	{
		p->set_error(ipv4_opt_invalid_len);
		return false;
	}

	if (opt.data == NULL)
	{
		p->set_error(ipv4_opt_malformed);
		return false;
	}

	const std::uint8_t* tag = opt.data + 4;
	std::uint16_t len = opt.len - 1 - 1 - 4;

	while (len)
	{
		if (len < 2)
		{
			p->set_error(ipv4_opt_malformed);
			return false;
		}

		std::uint8_t ttype = *(tag++);
		std::uint8_t tlen = *(tag++);

		if (tlen > len)
		{
			p->set_error(ipv4_opt_malformed);
			return false;
		}

		switch (ttype)
		{
		case 1:
		case 2:
		case 5:
		case 6:
		case 7:
			if ((tlen < 4) || (tlen > len))
			{
				p->set_error(ipv4_opt_malformed);
				return false;
			}

			if ((ttype != 7) && (*tag != 0))
			{
				p->set_error(ipv4_opt_malformed);
				return false;
			}

			tag += tlen - 2;
			len -= tlen;
			continue;

		case 0:
			p->set_error(ipv4_opt_malformed);
			return false;

		default:
			p->set_error(ipv4_opt_malformed);
			return false;
		}
	}

	return true;
}

bool pkt::ipv4::decode_options(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	ipv4_options opts;

	std::uint16_t plen = len;
	if (plen % 8)
		p->set_error(ipv4_opt_pad_required);

	while (plen)
	{
		p->ipv4vars.opt_cnt++;

		if (*pkt == ipv4_opt_eol)
		{
			p->ipv4vars.opts_set |= ipv4_opt_flag_eol;
			break;
		}
		else if (*pkt == ipv4_opt_nop)
		{
			p->ipv4vars.opts_set |= ipv4_opt_flag_nop;
			pkt++;
			plen--;
		}
		else if (plen < 2)
			break;
		else
		{
			if (*(pkt + 1) > plen)
			{
				p->set_error(ipv4_opt_invalid_len);
				return false;
			}
			ipv4_opt opt;
			opt.type = *pkt;
			opt.len = *(pkt + 1);
			if (plen > 2)
				opt.data = (pkt + 2);
			else
				opt.data = nullptr;
			if (opt.len > plen || opt.len < 2)
			{
				p->set_error(ipv4_opt_invalid_len);
				return false;
			}
			switch (opt.type)
			{
			case ipv4_opt_ts:
				if (opts.o_ts.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_timestamp(p, opt))
					return false;
				else
				{
					opts.o_ts = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_ts;
				}
				break;
			case ipv4_opt_rr:
				if (opts.o_rr.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_route(p, opt))
					return false;
				else
				{
					opts.o_rr = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_rr;
				}
				break;
			case ipv4_opt_qs:
				if (opts.o_qs.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_generic(p, opt))
					return false;
				else
				{
					opts.o_qs = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_qs;
				}
				break;
			case ipv4_opt_sec:
				if (opts.o_sec.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_generic(p, opt))
					return false;
				else
				{
					opts.o_sec = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_sec;
				}
				break;
			case ipv4_opt_lsrr:
				if (opts.o_lsrr.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_route(p, opt))
					return false;
				else
				{
					opts.o_lsrr = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_lsrr;
				}
				break;
			case ipv4_opt_cipso:
				if (opts.o_cipso.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_cipso(p, opt))
					return false;
				else
				{
					opts.o_cipso = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_cipso;
				}
				break;
			case ipv4_opt_sid:
				if (opts.o_sid.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_generic(p, opt))
					return false;
				else
				{
					opts.o_sid = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_sid;
				}
				break;
			case ipv4_opt_ssrr:
				if (opts.o_ssrr.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_route(p, opt))
					return false;
				else
				{
					opts.o_ssrr = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_ssrr;
				}
				break;
			case ipv4_opt_rtralt:
				if (opts.o_rtralt.type != 0)
					p->set_error(ipv4_opt_duplicate);
				else if (! validate_generic(p, opt))
					return false;
				else
				{
					opts.o_rtralt = opt;
					p->ipv4vars.opts_set |= ipv4_opt_flag_rtralt;
				}
				break;
			default:
				p->set_error(ipv4_opt_invalid);
				break;
			}
			pkt += opt.len;
			plen -= opt.len;
		}
	}

	return true;
}

bool pkt::ipv4::decode_packet(const std::shared_ptr<packet>& p,
		const std::uint8_t* pkt, const int& len)
{
	if (len < ipv4_header_len)
	{
		p->set_error(ipv4_pkt_too_small);
		return false;
	}

	if (ip_get_raw_ver(pkt) != 4)
	{
		p->set_error(ipv4_wrong_ip_ver);
		return false;
	}

	p->ipv4h = reinterpret_cast<ipv4_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->ipv4h == nullptr)
		return false;

	if (p->ipv4_get_hlen() < ipv4_header_len)
	{
		p->set_error(ipv4_hlen_too_small);
		return false;
	}

	if (p->ipv4_get_iplen() < p->ipv4_get_hlen())
	{
		p->set_error(ipv4_iplen_smaller_than_hlen);
		return false;
	}

	if (len < p->ipv4_get_iplen())
	{
		p->set_error(ipv4_trunc_pkt);
		return false;
	}

	p->set_ipv4_src_addr(&p->src);
	p->set_ipv4_dst_addr(&p->dst);

	std::uint8_t opt_len = p->ipv4_get_hlen() - ipv4_header_len;
	if (opt_len > 0)
		decode_options(p, pkt + ipv4_header_len, opt_len);

	return true;
}

bool pkt::ipv4::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_ipv4);

	if (! decode_packet(p, pkt, len))
	{
		p->ipv4h = nullptr;
		return false;
	}

	p->proto = p->ipv4_get_ipproto();

	if (p->ipv4_get_ipoffset() > 0 || p->ipv4_get_mf() == 1)
	{
		if (pq != nullptr)
		{
			std::shared_ptr<packet> rp = defrag_packet(tv, p, pq);
			if (rp != nullptr)
				pq->enque(rp);
		}
		p->flags |= pkt_is_fragmented;
		return true;
	}

	switch (p->ipv4_get_ipproto())
	{
	case IPPROTO_TCP:
		return tcp::decode(tv, p, pkt + p->ipv4_get_hlen(),
				p->ipv4_get_iplen() - p->ipv4_get_hlen(), pq);
	case IPPROTO_UDP:
		return udp::decode(tv, p, pkt + p->ipv4_get_hlen(),
				p->ipv4_get_iplen() - p->ipv4_get_hlen(), pq);
	case IPPROTO_ICMP:
		return icmpv4::decode(tv, p, pkt + p->ipv4_get_hlen(),
				p->ipv4_get_iplen() - p->ipv4_get_hlen(), pq);
	case IPPROTO_GRE:
		return gre::decode(tv, p, pkt + p->ipv4_get_hlen(),
				p->ipv4_get_iplen() - p->ipv4_get_hlen(), pq);
	case IPPROTO_SCTP:
		return sctp::decode(tv, p, pkt + p->ipv4_get_hlen(),
				p->ipv4_get_iplen() - p->ipv4_get_hlen(), pq);
	case IPPROTO_IPV6:
//		std::shared_ptr<packet> tp = packet_tunnel_pkt_setup(p,
//			pkt + p->ipv4_get_hlen(), p->ipv4_get_iplen() - p->ipv4_get_hlen(),
//			decode_tunnel_ipv6, pq);
//		if (tp != nullptr) {
//			pkt_set_src(tp, pkt_src_decoder_ipv4);
//			pq->enqueue(std::move(tp));
//		}
		break;
	case IPPROTO_IP:
//		if (p->ppph != NULL && ::ntohs(p->ppph->protocol) == PPP_VJ_UCOMP)
//			tcp::decode(tv, p, pkt + ipv4_get_hlen(p),
//				ipv4_get_iplen(p) - ipv4_get_hlen(p));
		break;
	case IPPROTO_ICMPV6:
		p->set_error(ipv4_with_icmpv6);
		break;
	}
	return true;
}

#if !defined(__PKT_INLINE__)
#include "pkt.ipv4.inl"
#endif

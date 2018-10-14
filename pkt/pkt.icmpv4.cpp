#include "pkt.packet.h"
#include "pkt.icmpv4.h"
#include "pkt.thread_vars.h"

bool pkt::icmpv4::decode_partial_ipv4(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	if (len < ipv4_header_len)
	{
		p->set_error(icmpv4_ipv4_trunc_pkt);
		return false;
	}

	ipv4_hdr* icmp4_ip4h =
			reinterpret_cast<ipv4_hdr *>(const_cast<uint8_t *>(pkt));

	if (icmp4_ip4h->get_ver() != 4)
	{
		p->set_error(icmpv4_ipv4_unknown_ver);
		return false;
	}

	p->icmpv4vars.emb_ipv4h = icmp4_ip4h;

	p->icmpv4vars.emb_ip4_src = icmp4_ip4h->get_ipsrc();
	p->icmpv4vars.emb_ip4_dst = icmp4_ip4h->get_ipdst();

	p->icmpv4vars.emb_ip4_hlen = icmp4_ip4h->get_hlen() << 2;

	switch (icmp4_ip4h->get_ipproto())
	{
	case IPPROTO_TCP:
		if (len >= ipv4_header_len + tcp_header_len)
		{
			p->icmpv4vars.emb_tcph = reinterpret_cast<tcp_hdr *>(
					const_cast<uint8_t *>(pkt + ipv4_header_len));
			p->icmpv4vars.emb_sport = ::ntohs(p->icmpv4vars.emb_tcph->th_sport);
			p->icmpv4vars.emb_dport = ::ntohs(p->icmpv4vars.emb_tcph->th_dport);
			p->icmpv4vars.emb_ip4_proto = IPPROTO_TCP;
		}
		else if (len >= ipv4_header_len + 4)
		{
			tcp_hdr* emb_tcph = reinterpret_cast<tcp_hdr *>(
					const_cast<uint8_t *>(pkt + ipv4_header_len));
			p->icmpv4vars.emb_tcph = nullptr;
			p->icmpv4vars.emb_sport = ::ntohs(emb_tcph->th_sport);
			p->icmpv4vars.emb_dport = ::ntohs(emb_tcph->th_dport);
			p->icmpv4vars.emb_ip4_proto = IPPROTO_TCP;
		}
		else
		{
			p->icmpv4vars.emb_sport = 0;
			p->icmpv4vars.emb_dport = 0;
		}
		break;

	case IPPROTO_UDP:
		if (len >= ipv4_header_len + udp_header_len)
		{
			p->icmpv4vars.emb_udph = reinterpret_cast<udp_hdr *>(
					const_cast<uint8_t *>(pkt + ipv4_header_len));
			p->icmpv4vars.emb_sport = ::ntohs(p->icmpv4vars.emb_udph->uh_sport);
			p->icmpv4vars.emb_dport = ::ntohs(p->icmpv4vars.emb_udph->uh_dport);
			p->icmpv4vars.emb_ip4_proto = IPPROTO_UDP;
		}
		else
		{
			p->icmpv4vars.emb_sport = 0;
			p->icmpv4vars.emb_dport = 0;
		}
		break;

	case IPPROTO_ICMP:
		if (len >= ipv4_header_len + icmpv4_header_len)
		{
			p->icmpv4vars.emb_icmpv4h = reinterpret_cast<icmpv4_hdr *>(
				const_cast<uint8_t *>(pkt + ipv4_header_len));
			p->icmpv4vars.emb_sport = 0;
			p->icmpv4vars.emb_dport = 0;
			p->icmpv4vars.emb_ip4_proto = IPPROTO_ICMP;
		}
		break;
	}

	return true;
}

bool pkt::icmpv4::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_icmpv4);

	if (len < icmpv4_header_len)
	{
		p->set_error(icmpv4_pkt_too_small);
		return false;
	}

	p->icmpv4h = reinterpret_cast<icmpv4_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->icmpv4h == nullptr)
		return false;

	p->proto = IPPROTO_ICMP;
	p->type = p->icmpv4h->ic_type;
	p->code = p->icmpv4h->ic_code;
	p->payload = pkt + icmpv4_header_len;
	p->payload_len = len - icmpv4_header_len;

	icmpv4_ext_hdr* icmpv4eh = reinterpret_cast<icmpv4_ext_hdr *>
			(const_cast<icmpv4_hdr *>(p->icmpv4h));

	switch (p->icmpv4_get_type())
	{
	case icmp_dest_unreach:
		if (p->icmpv4_get_code() > nr_icmp_unreach)
			p->set_error(icmpv4_unknown_code);
		else if (len > icmpv4_header_pkt_offset)
		{
			if (decode_partial_ipv4(p, pkt + icmpv4_header_pkt_offset,
					len - icmpv4_header_pkt_offset))
			{
				if (p->icmpv4_dest_unreach_is_valid())
					; // p->flow_setup_packet();
			}
		}
		break;
	case icmp_redirect:
		if (p->icmpv4_get_code() > icmp_redir_hosttos)
			p->set_error(icmpv4_unknown_code);
		else if (len > icmpv4_header_pkt_offset)
			decode_partial_ipv4(p, pkt + icmpv4_header_pkt_offset,
				len - icmpv4_header_pkt_offset);
		break;
	case icmp_time_exceeded:
		if (p->icmpv4_get_code() > icmp_exc_fragtime)
			p->set_error(icmpv4_unknown_code);
		else if (len > icmpv4_header_pkt_offset)
			decode_partial_ipv4(p, pkt + icmpv4_header_pkt_offset,
				len - icmpv4_header_pkt_offset);
		break;
	case icmp_source_quench:
	case icmp_parameterprob:
		if (p->icmpv4_get_code() != 0)
			p->set_error(icmpv4_unknown_code);
		else if (len > icmpv4_header_pkt_offset)
			decode_partial_ipv4(p, pkt + icmpv4_header_pkt_offset,
				len - icmpv4_header_pkt_offset);
		break;
	case icmp_echoreply:
	case icmp_echo:
	case icmp_timestamp:
	case icmp_timestampreply:
	case icmp_info_request:
	case icmp_info_reply:
	case icmp_address:
	case icmp_addressreply:
		p->icmpv4vars.id = icmpv4eh->ic_id;
		p->icmpv4vars.seq = icmpv4eh->ic_seq;
		if (p->icmpv4h->ic_code != 0)
			p->set_error(icmpv4_unknown_code);
		break;
	default:
		p->set_error(icmpv4_unknown_type);
	}

	return true;
}

#if !defined(__PKT_INLINE__)
#include "pkt.icmpv4.inl"
#endif

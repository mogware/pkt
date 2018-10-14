#include "pkt.packet.h"
#include "pkt.icmpv6.h"
#include "pkt.thread_vars.h"

/* Destination Unreachable Message (type=1) Code: */
static const std::uint8_t icmp6_dst_unreach_noroute = 0;
static const std::uint8_t icmp6_dst_unreach_admin = 1;
static const std::uint8_t icmp6_dst_unreach_beyondscope = 2;
static const std::uint8_t icmp6_dst_unreach_addr = 3;
static const std::uint8_t icmp6_dst_unreach_noport = 4;
static const std::uint8_t icmp6_dst_unreach_failedpolicy = 5;
static const std::uint8_t icmp6_dst_unreach_rejectroute = 6;

/* Time Exceeded Message (type=3) Code: */
static const std::uint8_t icmp6_time_exceed_transit = 0;
static const std::uint8_t icmp6_time_exceed_reassembly = 1;

/* Parameter Problem Message (type=4) Code: */
static const std::uint8_t icmp6_paramprob_header = 0;
static const std::uint8_t icmp6_paramprob_nextheader = 1;
static const std::uint8_t icmp6_paramprob_option = 2;

bool pkt::icmpv6::decode_partial_ipv6(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	if (len < ipv6_header_len)
	{
		p->set_error(icmpv6_ipv6_trunc_pkt);
		return false;
	}

	ipv6_hdr* icmp6_ip6h =
		reinterpret_cast<ipv6_hdr *>(const_cast<uint8_t *>(pkt));

	if (icmp6_ip6h->get_ver() != 6)
	{
		p->set_error(icmpv6_ipv6_unknown_ver);
		return false;
	}

	p->icmpv6vars.emb_ipv6h = icmp6_ip6h;

	p->icmpv6vars.emb_ip6_src[0] = icmp6_ip6h->ip6_src[0];
	p->icmpv6vars.emb_ip6_src[1] = icmp6_ip6h->ip6_src[1];
	p->icmpv6vars.emb_ip6_src[2] = icmp6_ip6h->ip6_src[2];
	p->icmpv6vars.emb_ip6_src[3] = icmp6_ip6h->ip6_src[3];

	p->icmpv6vars.emb_ip6_dst[0] = icmp6_ip6h->ip6_dst[0];
	p->icmpv6vars.emb_ip6_dst[1] = icmp6_ip6h->ip6_dst[1];
	p->icmpv6vars.emb_ip6_dst[2] = icmp6_ip6h->ip6_dst[2];
	p->icmpv6vars.emb_ip6_dst[3] = icmp6_ip6h->ip6_dst[3];

	p->icmpv6vars.emb_ip6_proto_next = icmp6_ip6h->ip6_nxt;

	switch (icmp6_ip6h->ip6_nxt)
	{
	case IPPROTO_TCP:
		if (len >= ipv6_header_len + tcp_header_len)
		{
			p->icmpv4vars.emb_tcph = reinterpret_cast<tcp_hdr *>(
				const_cast<uint8_t *>(pkt + ipv6_header_len));
			p->icmpv6vars.emb_sport = ::ntohs(p->icmpv6vars.emb_tcph->th_sport);
			p->icmpv6vars.emb_dport = ::ntohs(p->icmpv6vars.emb_tcph->th_dport);
		}
		else
		{
			p->icmpv6vars.emb_sport = 0;
			p->icmpv6vars.emb_dport = 0;
		}
		break;

	case IPPROTO_UDP:
		if (len >= ipv6_header_len + udp_header_len)
		{
			p->icmpv6vars.emb_udph = reinterpret_cast<udp_hdr *>(
				const_cast<uint8_t *>(pkt + ipv6_header_len));
			p->icmpv6vars.emb_sport = ::ntohs(p->icmpv6vars.emb_udph->uh_sport);
			p->icmpv6vars.emb_dport = ::ntohs(p->icmpv6vars.emb_udph->uh_dport);
		}
		else
		{
			p->icmpv6vars.emb_sport = 0;
			p->icmpv6vars.emb_dport = 0;
		}
		break;

	case IPPROTO_ICMPV6:
		if (len >= ipv6_header_len + icmpv6_header_len)
		{
			p->icmpv4vars.emb_icmpv4h = reinterpret_cast<icmpv4_hdr *>(
				const_cast<uint8_t *>(pkt + ipv6_header_len));
			p->icmpv4vars.emb_sport = 0;
			p->icmpv4vars.emb_dport = 0;
		}
		break;
	}

	return false;
}

bool pkt::icmpv6::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	int full_hdr = 0;

	tv->cc.incr(counter_icmpv6);

	if (len < icmpv6_header_len)
	{
		p->set_error(icmpv6_pkt_too_small);
		return false;
	}

	p->icmpv6h = reinterpret_cast<icmpv6_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->icmpv6h == nullptr)
		return false;

	p->proto = IPPROTO_ICMPV6;
	p->type = p->icmpv6h->ic_type;
	p->code = p->icmpv6h->ic_code;
	p->payload = pkt + icmpv6_header_len;
	p->payload_len = len - icmpv6_header_len;

	switch (p->icmpv6_get_type())
	{
	case icmp6_dst_unreach:
		if (p->icmpv6_get_code() > icmp6_dst_unreach_rejectroute)
			p->set_error(icmpv6_unknown_code);
		else
		{
			decode_partial_ipv6(p, pkt + icmpv6_header_len,
				len - icmpv6_header_len);
			full_hdr = 1;
		}
		break;
	case icmp6_packet_too_big:
		if (p->icmpv6_get_code() != 0)
			p->set_error(icmpv6_unknown_code);
		else
		{
			p->icmpv6vars.mtu = p->icmpv6_get_mtu();
			decode_partial_ipv6(p, pkt + icmpv6_header_len,
				len - icmpv6_header_len);
			full_hdr = 1;
		}
		break;
	case icmp6_time_exceeded:
		if (p->icmpv6_get_code() > icmp6_time_exceed_reassembly)
			p->set_error(icmpv6_unknown_code);
		else
		{
			decode_partial_ipv6(p, pkt + icmpv6_header_len,
				len - icmpv6_header_len);
			full_hdr = 1;
		}
		break;
	case icmp6_param_prob:
		if (p->icmpv6_get_code() > icmp6_paramprob_option)
			p->set_error(icmpv6_unknown_code);
		else
		{
			p->icmpv6vars.error_ptr = p->icmpv6_get_error_ptr();
			decode_partial_ipv6(p, pkt + icmpv6_header_len,
				len - icmpv6_header_len);
			full_hdr = 1;
		}
		break;
	case icmp6_echo_request:
	case icmp6_echo_reply:
		if (p->icmpv6_get_code() != 0)
			p->set_error(icmpv6_unknown_code);
		else
		{
			p->icmpv6vars.id = p->icmpv6h->ic_icmpv6i.ic_id;
			p->icmpv6vars.seq = p->icmpv6h->ic_icmpv6i.ic_seq;
			full_hdr = 1;
		}
		break;
	case nd_router_solicit:
	case nd_router_advert:
	case nd_neighbor_solicit:
	case nd_neighbor_advert:
	case nd_redirect:
	case nd_inverse_advert:
	case mld_v2_list_report:
	case home_agent_ad_request:
	case home_agent_ad_reply:
	case mobile_prefix_solicit:
	case mobile_prefix_advert:
	case cert_path_solicit:
	case cert_path_advert:
	case fmipv6_msg:
	case locator_udate_msg:
	case dupl_addr_request:
	case dupl_addr_confirm:
	case mpl_control_msg:
		if (p->icmpv6_get_code() != 0)
			p->set_error(icmpv6_unknown_code);
		break;
	case mld_listener_query:
	case mld_listener_report:
	case mld_listener_reduction:
		if (p->icmpv6_get_code() != 0)
			p->set_error(icmpv6_unknown_code);
		if (p->ipv6_get_hlim() != 1)
			p->set_error(icmpv6_mld_message_with_invalid_hl);
		break;
	case icmp6_rr:
		if (p->icmpv6_get_code() > 2 && p->icmpv6_get_code() != 255)
			p->set_error(icmpv6_unknown_code);
		break;
	case icmp6_ni_query:
	case icmp6_ni_reply:
		if (p->icmpv6_get_code() > 2)
			p->set_error(icmpv6_unknown_code);
		break;
	case rpl_control_msg:
		if (p->icmpv6_get_code() > 3 && p->icmpv6_get_code() < 128)
			p->set_error(icmpv6_unknown_code);
		if (p->icmpv6_get_code() > 132)
			p->set_error(icmpv6_unknown_code);
		break;
	case icmp6_mobile_experimental:
	case mc_router_advert:
	case mc_router_solicit:
	case mc_router_terminate:
		break;
	default:
		if (p->icmpv6_get_type() > 4 && p->icmpv6_get_type() < 100)
			p->set_error(icmpv6_unassigned_type);
		else if (p->icmpv6_get_type() >= 100 && p->icmpv6_get_type() < 102)
			p->set_error(icmpv6_experimentation_type);
		else  if (p->icmpv6_get_type() >= 102 && p->icmpv6_get_type() < 127)
			p->set_error(icmpv6_unassigned_type);
		else if (p->icmpv6_get_type() >= 160 && p->icmpv6_get_type() < 200)
			p->set_error(icmpv6_unassigned_type);
		else if (p->icmpv6_get_type() >= 200 && p->icmpv6_get_type() < 202)
			p->set_error(icmpv6_experimentation_type);
		else if (p->icmpv6_get_type() >= 202)
			p->set_error(icmpv6_unassigned_type);
		else
			p->set_error(icmpv6_unknown_type);
		break;
	}

	if (!full_hdr)
	{
		if (p->payload_len >= 4)
		{
			p->payload_len -= 4;
			p->payload = pkt + 4;
		}
		else
		{
			p->payload_len = 0;
			p->payload = NULL;
		}
	}

	// p->flow_setup_packet();

	return true;
}

#if !defined(__PKT_INLINE__)
#include "pkt.icmpv6.inl"
#endif
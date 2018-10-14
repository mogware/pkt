#include "pkt.decode.h"
#include "pkt.packet.h"
#include "pkt.ipv4.h"
#include "pkt.tcp.h"
#include "pkt.udp.h"
#include "pkt.icmpv4.h"
#include "pkt.thread_vars.h"
#include "pkt.counter.h"
#include "pkt.defrag_tracker.h"
#include "pkt.defrag_tracker_map.h"

const std::uint16_t pkt::decode::ethernet_header_len;

const std::uint16_t pkt::decode::ethernet_type_pup;
const std::uint16_t pkt::decode::ethernet_type_ip;
const std::uint16_t pkt::decode::ethernet_type_ipv6;
const std::uint16_t pkt::decode::ethernet_type_pppoe_sess;
const std::uint16_t pkt::decode::ethernet_type_pppoe_disc;
const std::uint16_t pkt::decode::ethernet_type_8021ad;
const std::uint16_t pkt::decode::ethernet_type_vlan;
const std::uint16_t pkt::decode::ethernet_type_8021qinq;
const std::uint16_t pkt::decode::ethernet_type_mpls_unicast;
const std::uint16_t pkt::decode::ethernet_type_mpls_multicast;
const std::uint16_t pkt::decode::ethernet_type_dce;
const std::uint16_t pkt::decode::ethernet_type_erspan;
const std::uint16_t pkt::decode::ethernet_type_bridge;
const std::uint16_t pkt::decode::ethernet_type_gre_ppp;

const std::uint16_t pkt::decode::sll_header_len;

const std::uint16_t pkt::decode::ipv4_header_len;
const std::uint16_t pkt::decode::ipv6_header_len;

const std::uint16_t pkt::decode::tcp_header_len;

const std::uint8_t pkt::decode::tcp_opt_eol;
const std::uint8_t pkt::decode::tcp_opt_nop;
const std::uint8_t pkt::decode::tcp_opt_mss;
const std::uint8_t pkt::decode::tcp_opt_ws;
const std::uint8_t pkt::decode::tcp_opt_sackok;
const std::uint8_t pkt::decode::tcp_opt_sack;
const std::uint8_t pkt::decode::tcp_opt_ts;

const std::uint8_t pkt::decode::tcp_opt_ws_len;
const std::uint8_t pkt::decode::tcp_opt_ts_len;
const std::uint8_t pkt::decode::tcp_opt_mss_len;
const std::uint8_t pkt::decode::tcp_opt_sackok_len;
const std::uint8_t pkt::decode::tcp_opt_sack_min_len;
const std::uint8_t pkt::decode::tcp_opt_sack_max_len;

const std::uint16_t pkt::decode::udp_header_len;

const std::uint16_t pkt::decode::icmpv4_header_len;
const std::uint16_t pkt::decode::icmpv4_header_pkt_offset;

const std::uint8_t pkt::decode::icmp_echoreply;
const std::uint8_t pkt::decode::icmp_dest_unreach;
const std::uint8_t pkt::decode::icmp_source_quench;
const std::uint8_t pkt::decode::icmp_redirect;
const std::uint8_t pkt::decode::icmp_echo;
const std::uint8_t pkt::decode::icmp_time_exceeded;
const std::uint8_t pkt::decode::icmp_parameterprob;
const std::uint8_t pkt::decode::icmp_timestamp;
const std::uint8_t pkt::decode::icmp_timestampreply;
const std::uint8_t pkt::decode::icmp_info_request;
const std::uint8_t pkt::decode::icmp_info_reply;
const std::uint8_t pkt::decode::icmp_address;
const std::uint8_t pkt::decode::icmp_addressreply;

const std::uint8_t pkt::decode::icmp_redir_hosttos;
const std::uint8_t pkt::decode::icmp_exc_fragtime;

const std::uint8_t pkt::decode::nr_icmp_unreach;

const std::uint16_t pkt::decode::icmpv6_header_len;
const std::uint16_t pkt::decode::icmpv6_header_pkt_offset;

const std::uint8_t pkt::decode::icmp6_dst_unreach;
const std::uint8_t pkt::decode::icmp6_packet_too_big;
const std::uint8_t pkt::decode::icmp6_time_exceeded;
const std::uint8_t pkt::decode::icmp6_param_prob;

const std::uint8_t pkt::decode::icmp6_echo_request;
const std::uint8_t pkt::decode::icmp6_echo_reply;

const std::uint8_t pkt::decode::mld_listener_query;
const std::uint8_t pkt::decode::mld_listener_report;
const std::uint8_t pkt::decode::mld_listener_reduction;

const std::uint8_t pkt::decode::nd_router_solicit;
const std::uint8_t pkt::decode::nd_router_advert;
const std::uint8_t pkt::decode::nd_neighbor_solicit;
const std::uint8_t pkt::decode::nd_neighbor_advert;
const std::uint8_t pkt::decode::nd_redirect;

const std::uint8_t pkt::decode::icmp6_rr;
const std::uint8_t pkt::decode::icmp6_ni_query;
const std::uint8_t pkt::decode::icmp6_ni_reply;
const std::uint8_t pkt::decode::nd_inverse_solicit;
const std::uint8_t pkt::decode::nd_inverse_advert;
const std::uint8_t pkt::decode::mld_v2_list_report;
const std::uint8_t pkt::decode::home_agent_ad_request;
const std::uint8_t pkt::decode::home_agent_ad_reply;
const std::uint8_t pkt::decode::mobile_prefix_solicit;
const std::uint8_t pkt::decode::mobile_prefix_advert;
const std::uint8_t pkt::decode::cert_path_solicit;
const std::uint8_t pkt::decode::cert_path_advert;
const std::uint8_t pkt::decode::icmp6_mobile_experimental;
const std::uint8_t pkt::decode::mc_router_advert;
const std::uint8_t pkt::decode::mc_router_solicit;
const std::uint8_t pkt::decode::mc_router_terminate;
const std::uint8_t pkt::decode::fmipv6_msg;
const std::uint8_t pkt::decode::rpl_control_msg;
const std::uint8_t pkt::decode::locator_udate_msg;
const std::uint8_t pkt::decode::dupl_addr_request;
const std::uint8_t pkt::decode::dupl_addr_confirm;
const std::uint8_t pkt::decode::mpl_control_msg;

const std::uint16_t pkt::decode::gre_header_len;
const std::uint16_t pkt::decode::grev1_header_len;

const std::uint16_t pkt::decode::gre_chksum_len;
const std::uint16_t pkt::decode::gre_offset_len;
const std::uint16_t pkt::decode::gre_key_len;
const std::uint16_t pkt::decode::gre_seq_len;
const std::uint16_t pkt::decode::gre_sre_hdr_len;
const std::uint16_t pkt::decode::grev1_ack_len;

const std::uint16_t pkt::decode::mpls_header_len;

const std::uint16_t pkt::decode::sctp_header_len;

const std::uint16_t pkt::decode::vlan_header_len;

const std::uint16_t pkt::decode::ppp_header_len;
const std::uint16_t pkt::decode::pppoe_sess_header_len;
const std::uint16_t pkt::decode::pppoe_disc_header_min_len;

const std::uint16_t pkt::decode::ppp_ip;
const std::uint16_t pkt::decode::ppp_ipv6;
const std::uint16_t pkt::decode::ppp_vj_ucomp;

std::uint8_t pkt::decode::ip_get_raw_ver(const std::uint8_t* pkt)
{
	return (pkt[0] & 0xf0) >> 4;
}

std::shared_ptr<pkt::packet> pkt::decode::packet_tunnel_pkt_setup(
	const std::shared_ptr<pkt::packet>& p, const std::uint8_t* pkt,
	const std::uint16_t& len, const int& proto)
{
	return nullptr;	// TODO
}

std::shared_ptr<pkt::packet> pkt::decode::defrag_packet(
	const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<pkt::packet>& p,
	const std::shared_ptr<pkt::packet_queue>& pq)
{
	if (p->is_ipv4())
	{
		if (p->ipv4_get_ipoffset() == 0 && p->ipv4_get_mf() != 1)
			return nullptr;
		tv->cc.incr(counter_defrag_ipv4_fragments);
	}
	else if (p->is_ipv6())
	{
		if (p->ipv6_get_fh_offset() == 0 && !p->ipv6_get_fh_flag())
			return nullptr;
		tv->cc.incr(counter_defrag_ipv6_fragments);
	}

	static pkt::defrag_tracker_map map;
	std::shared_ptr<pkt::defrag_tracker> df = map.get_tracker(p);
	if (df == nullptr)
		return nullptr;

	std::shared_ptr<pkt::packet> rp = df->insert_frag(tv, p, pq);
	df->release();

	return rp;
}

void pkt::decode::update_packet_counters(
		const std::shared_ptr<pkt::thread_vars>& tv,
		const std::shared_ptr<pkt::packet>& p)
{
	tv->cc.incr(counter_pkts);
	tv->cc.add(counter_bytes, p->pkt.size());
}

#ifndef __PKT_DECODE__
#define __PKT_DECODE__

#include <cstdint>
#include <memory>

#include "pkt.config.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	enum {
		decode_tunnel_ethernet,
		decode_tunnel_erspan,
		decode_tunnel_vlan,
		decode_tunnel_ipv4,
		decode_tunnel_ipv6,
		decode_tunnel_ppp
	};

	struct decode
	{
		static const std::uint16_t ethernet_header_len = 14;
		static const std::uint16_t ethernet_dce_header_len = 16;

		static const std::uint16_t ethernet_type_pup = 0x0200;
		static const std::uint16_t ethernet_type_ip = 0x0800;
		static const std::uint16_t ethernet_type_ipv6 = 0x86dd;
		static const std::uint16_t ethernet_type_pppoe_sess = 0x8864;
		static const std::uint16_t ethernet_type_pppoe_disc = 0x8863;
		static const std::uint16_t ethernet_type_8021ad = 0x88a8;
		static const std::uint16_t ethernet_type_vlan = 0x8100;
		static const std::uint16_t ethernet_type_8021qinq = 0x9100;
		static const std::uint16_t ethernet_type_mpls_unicast = 0x8847;
		static const std::uint16_t ethernet_type_mpls_multicast = 0x8848;
		static const std::uint16_t ethernet_type_dce = 0x8903;
		static const std::uint16_t ethernet_type_erspan = 0x88BE;
		static const std::uint16_t ethernet_type_bridge = 0x6558;
		static const std::uint16_t ethernet_type_gre_ppp = 0x880b;

		static const std::uint16_t sll_header_len = 16;

		static const std::uint16_t ipv4_header_len = 20;

		static const std::uint16_t ipv6_header_len = 40;

		static const std::uint16_t tcp_header_len = 20;

		static const std::uint8_t tcp_opt_eol = 0x00;
		static const std::uint8_t tcp_opt_nop = 0x01;
		static const std::uint8_t tcp_opt_mss = 0x02;
		static const std::uint8_t tcp_opt_ws = 0x03;
		static const std::uint8_t tcp_opt_sackok = 0x04;
		static const std::uint8_t tcp_opt_sack = 0x05;
		static const std::uint8_t tcp_opt_ts = 0x08;

		static const std::uint8_t tcp_opt_ws_len = 3;
		static const std::uint8_t tcp_opt_ts_len = 10;
		static const std::uint8_t tcp_opt_mss_len = 4;
		static const std::uint8_t tcp_opt_sackok_len = 2;
		static const std::uint8_t tcp_opt_sack_min_len = 10;
		static const std::uint8_t tcp_opt_sack_max_len = 34;

		static const std::uint16_t udp_header_len = 8;

		static const std::uint16_t icmpv4_header_len = 8;
		static const std::uint16_t icmpv4_header_pkt_offset = 8;

		static const std::uint8_t icmp_echoreply = 0;
		static const std::uint8_t icmp_dest_unreach = 3;
		static const std::uint8_t icmp_source_quench = 4;
		static const std::uint8_t icmp_redirect = 5;
		static const std::uint8_t icmp_echo = 8;
		static const std::uint8_t icmp_time_exceeded = 11;
		static const std::uint8_t icmp_parameterprob = 12;
		static const std::uint8_t icmp_timestamp = 13;
		static const std::uint8_t icmp_timestampreply = 14;
		static const std::uint8_t icmp_info_request = 15;
		static const std::uint8_t icmp_info_reply = 16;
		static const std::uint8_t icmp_address = 17;
		static const std::uint8_t icmp_addressreply = 18;

		static const std::uint8_t icmp_redir_hosttos = 3;
		static const std::uint8_t icmp_exc_fragtime = 1;

		static const std::uint8_t nr_icmp_unreach = 15;

		static const std::uint16_t icmpv6_header_len = 8;
		static const std::uint16_t icmpv6_header_pkt_offset = 8;

		static const std::uint8_t icmp6_dst_unreach = 1;
		static const std::uint8_t icmp6_packet_too_big = 2;
		static const std::uint8_t icmp6_time_exceeded = 3;
		static const std::uint8_t icmp6_param_prob = 4;

		static const std::uint8_t icmp6_echo_request = 128;
		static const std::uint8_t icmp6_echo_reply = 129;

		static const std::uint8_t mld_listener_query = 130;
		static const std::uint8_t mld_listener_report = 131;
		static const std::uint8_t mld_listener_reduction = 132;

		static const std::uint8_t nd_router_solicit = 133;
		static const std::uint8_t nd_router_advert = 134;
		static const std::uint8_t nd_neighbor_solicit = 135;
		static const std::uint8_t nd_neighbor_advert = 136;
		static const std::uint8_t nd_redirect = 137;

		static const std::uint8_t icmp6_rr = 138;
		static const std::uint8_t icmp6_ni_query = 139;
		static const std::uint8_t icmp6_ni_reply = 140;
		static const std::uint8_t nd_inverse_solicit = 141;
		static const std::uint8_t nd_inverse_advert = 142;
		static const std::uint8_t mld_v2_list_report = 143;
		static const std::uint8_t home_agent_ad_request = 144;
		static const std::uint8_t home_agent_ad_reply = 145;
		static const std::uint8_t mobile_prefix_solicit = 146;
		static const std::uint8_t mobile_prefix_advert = 147;
		static const std::uint8_t cert_path_solicit = 148;
		static const std::uint8_t cert_path_advert = 149;
		static const std::uint8_t icmp6_mobile_experimental = 150;
		static const std::uint8_t mc_router_advert = 151;
		static const std::uint8_t mc_router_solicit = 152;
		static const std::uint8_t mc_router_terminate = 153;
		static const std::uint8_t fmipv6_msg = 154;
		static const std::uint8_t rpl_control_msg = 155;
		static const std::uint8_t locator_udate_msg = 156;
		static const std::uint8_t dupl_addr_request = 157;
		static const std::uint8_t dupl_addr_confirm = 158;
		static const std::uint8_t mpl_control_msg = 159;

		static const std::uint16_t gre_header_len = 4;
		static const std::uint16_t grev1_header_len = 8;

		static const std::uint16_t gre_chksum_len = 2;
		static const std::uint16_t gre_offset_len = 2;
		static const std::uint16_t gre_key_len = 4;
		static const std::uint16_t gre_seq_len = 4;
		static const std::uint16_t gre_sre_hdr_len = 4;
		static const std::uint16_t grev1_ack_len = 4;

		static const std::uint16_t mpls_header_len = 4;

		static const std::uint16_t sctp_header_len = 12;

		static const std::uint16_t vlan_header_len = 4;

		static const std::uint16_t ppp_header_len = 4;
		static const std::uint16_t pppoe_sess_header_len = 8;
		static const std::uint16_t pppoe_disc_header_min_len = 6;

		static const std::uint16_t ppp_ip = 0x0021;
		static const std::uint16_t ppp_ipv6 = 0x0057;
		static const std::uint16_t ppp_vj_ucomp = 0x002f;

		static std::uint8_t ip_get_raw_ver(const std::uint8_t* pkt);

		static std::shared_ptr<packet> packet_tunnel_pkt_setup(
			const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
			const std::uint16_t& len, const int& proto);

		static std::shared_ptr<packet> defrag_packet(
			const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::shared_ptr<packet_queue>& pq);

		static void update_packet_counters(
			const std::shared_ptr<pkt::thread_vars>& tv,
			const std::shared_ptr<pkt::packet>& p);
	};
}

#endif

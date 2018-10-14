#ifndef __PKT_PACKET__
#define __PKT_PACKET__

#include <memory>
#include <bitset>
#include <vector>

#include "pkt.ethernet.h"
#include "pkt.ipv4.h"
#include "pkt.ipv6.h"
#include "pkt.tcp.h"
#include "pkt.udp.h"
#include "pkt.icmpv4.h"
#include "pkt.icmpv6.h"
#include "pkt.gre.h"
#include "pkt.sctp.h"
#include "pkt.vlan.h"
#include "pkt.ppp.h"
#include "pkt.pppoe_disc.h"
#include "pkt.pppoe_sess.h"

namespace pkt
{
	struct address
	{
		std::uint8_t family;
		union
		{
			std::uint32_t data32[4];
			std::uint16_t data16[8];
			std::uint8_t data8[16];
		};

		address()
		{
			std::memset(this, 0, sizeof(address));
		}
	};

	enum
	{
		pkt_nopacket_inspection		= 1 << 0,
		pkt_nopayload_inspection	= 1 << 1,
		pkt_alloc					= 1 << 2,
		pkt_has_tag					= 1 << 3,
		pkt_stream_add				= 1 << 4,
		pkt_stream_est				= 1 << 5,
		pkt_stream_eof				= 1 << 6,
		pkt_has_flow				= 1 << 7,
		pkt_pseudo_stream_end		= 1 << 8,
		pkt_stream_modified			= 1 << 9,
		pkt_mark_modified			= 1 << 10,
		pkt_stream_nopcaplog		= 1 << 11,
		pkt_tunnel					= 1 << 12,
		pkt_tunnel_verdicted		= 1 << 13,
		pkt_ignore_checksum			= 1 << 14,
		pkt_zero_copy				= 1 << 15,
		pkt_host_src_looked_up		= 1 << 16,
		pkt_host_dst_looked_up		= 1 << 17,
		pkt_is_fragmented 			= 1 << 18,
		pkt_is_invalid				= 1 << 19,
		pkt_profile					= 1 << 20,
		pkt_wants_flow				= 1 << 21,
		pkt_proto_detect_ts_done	= 1 << 22,
		pkt_proto_detect_tc_done	= 1 << 23,
		pkt_rebuilt_fragment		= 1 << 24,
		pkt_detect_has_streamdata	= 1 << 25,
		pkt_pseudo_detectlog_flush  = 1 << 26
	};

	enum
	{
		null_pkt_too_small,
		null_unsupported_type,

		raw_invalid_ipv,

		sll_pkt_too_small,
		sll_unsupported_proto,

		ethernet_pkt_too_small,

		ipv4_pkt_too_small,
		ipv4_wrong_ip_ver,
		ipv4_hlen_too_small,
		ipv4_iplen_smaller_than_hlen,
		ipv4_trunc_pkt,
		ipv4_with_icmpv6,
		ipv4_opt_invalid_len,
		ipv4_opt_invalid,
		ipv4_opt_duplicate,
		ipv4_opt_malformed,
		ipv4_opt_pad_required,

		ipv6_pkt_too_small,
		ipv6_wrong_ip_ver,
		ipv6_trunc_pkt,
		ipv6_data_after_none_header,
		ipv6_with_icmpv4,
		ipv6_trunc_exthdr,
		ipv6_exthdr_ah_res_not_null,
		ipv6_exthdr_dupl_ah,
		ipv6_exthdr_dupl_eh,
		ipv6_unknown_next_header,
		ipv6_exthdr_rh_type_0,
		ipv6_exthdr_invalid_optlen,
		ipv6_exthdr_dupl_hh,
		ipv6_exthdr_zero_len_padn,
		ipv6_fh_non_zero_res_field,
		ipv6_exthdr_dupl_fh,
		ipv6_exthdr_useless_fh,
		ipv6_hopopts_unknown_opt,
		ipv6_dstopts_unknown_opt,
		ipv6_hopopts_only_padding,
		ipv6_dstopts_only_padding,
		ipv4_in_ipv6_pkt_too_small,
		ipv4_in_ipv6_wrong_ip_ver,
		ipv6_in_ipv6_pkt_too_small,
		ipv6_in_ipv6_wrong_ip_ver,

		tcp_pkt_too_small,
		tcp_hlen_too_small,
		tcp_invalid_optlen,
		tcp_opt_invalid_len,
		tcp_opt_duplicate,

		udp_pkt_too_small,
		udp_len_invalid,

		icmpv4_pkt_too_small,
		icmpv4_unknown_code,
		icmpv4_unknown_type,
		icmpv4_ipv4_trunc_pkt,
		icmpv4_ipv4_unknown_ver,

		icmpv6_pkt_too_small,
		icmpv6_unknown_code,
		icmpv6_unknown_type,
		icmpv6_mld_message_with_invalid_hl,
		icmpv6_unassigned_type,
		icmpv6_experimentation_type,
		icmpv6_ipv6_trunc_pkt,
		icmpv6_ipv6_unknown_ver,

		gre_pkt_too_small,
		gre_wrong_version,
		gre_version0_recur,
		gre_version0_flags,
		gre_version0_hdr_too_big,
		gre_version0_malformed_sre_hdr,
		gre_version1_chksum,
		gre_version1_route,
		gre_version1_ssr,
		gre_version1_recur,
		gre_version1_flags,
		gre_version1_wrong_protocol,
		gre_version1_no_key,
		gre_version1_hdr_too_big,

		mpls_header_too_small,
		mpls_bad_label_router_alert,
		mpls_bad_label_implicit_null,
		mpls_bad_label_reserved,
		mpls_unknown_payload_type,

		dce_pkt_too_small,

		sctp_pkt_too_small,

		vlan_header_too_small,
		vlan_header_too_many_layers,
		vlan_unknown_type,

		ppp_unsupported_proto,
		ppp_pkt_too_small,
		pppvju_pkt_too_small,
		pppipv4_pkt_too_small,
		pppipv6_pkt_too_small,
		pppoe_wrong_code,
		pppoe_pkt_too_small,

		packet_error_max
	};

	struct packet
	{
		std::vector<std::uint8_t> pkt;

		address src;
		address dst;
		union
		{
			std::uint16_t sport;
			std::uint8_t type;
		};
		union
		{
			std::uint16_t dport;
			std::uint8_t code;
		};
		std::uint8_t proto;

		std::uint16_t vlan_id[2];
		std::uint8_t vlan_idx;

		std::uint32_t flags;

		const ethernet_hdr* ethh;

		const ipv4_hdr* ipv4h;
		const ipv6_hdr* ipv6h;
		union
		{
			ipv4_vars ipv4vars;
			struct {
				ipv6_vars ipv6vars;
				ipv6_ext_hdrs ipv6eh;
			};
		};

		const tcp_hdr* tcph;
		union
		{
			tcp_vars tcpvars;
			icmpv4_vars icmpv4vars;
			icmpv6_vars icmpv6vars;
		};

		const udp_hdr* udph;
		const sctp_hdr* sctph;

		const icmpv4_hdr* icmpv4h;
		const icmpv6_hdr* icmpv6h;

		const ppp_hdr *ppph;
		const pppoe_sess_hdr* pppoesh;
		const pppoe_disc_hdr* pppoedh;

		const gre_hdr* greh;

		vlan_hdr* vlanh[2];

		const std::uint8_t* payload;
		std::uint16_t payload_len;

		const std::uint8_t* ext_pkt;
		std::uint32_t pktlen;

		std::bitset<packet_error_max> errors;

		packet()
		{
			std::memset(this, 0, sizeof(packet));
		}

		~packet()
		{
		}

		static std::shared_ptr<packet> of(const std::uint8_t* pkt,
			const std::uint16_t& len)
		{
			std::shared_ptr<packet> p = std::make_shared<packet>();
			p->pkt.assign(pkt, pkt + len);
			return p;
		}

		void set_error(int err)
		{
			errors.set(err);
		}

		bool isset_error(int err) const
		{
			return errors.test(err);
		}

		bool has_error(void) const
		{
			return errors.any();
		}

		const std::uint8_t* get_pkt_data(void) const
		{
			return ext_pkt != nullptr ? ext_pkt :
				reinterpret_cast<const std::uint8_t *>(this + 1);
		}

		std::uint32_t get_pkt_len(void) const
		{
			return pktlen;
		}

		std::uint16_t get_src_port(void) const
		{
			return sport;
		}

		std::uint16_t get_dst_port(void) const
		{
			return dport;
		}

		std::uint32_t get_ipv4_src_addr(void) const
		{
			return src.data32[0];
		}

		std::uint32_t get_ipv4_dst_addr(void) const
		{
			return dst.data32[0];
		}

		std::uint8_t* get_src_addr(void) const
		{
			return reinterpret_cast<std::uint8_t*>(
					const_cast<std::uint32_t *>(src.data32));
		}

		std::uint8_t* get_dst_addr(void) const
		{
			return reinterpret_cast<std::uint8_t*>(
					const_cast<std::uint32_t *>(dst.data32));
		}

		bool is_ipv4(void) const
		{
			return ipv4h != nullptr;
		}

		bool is_ipv6(void) const
		{
			return ipv6h != nullptr;
		}

		bool is_tcp(void) const
		{
			return tcph != nullptr;
		}

		bool is_udp(void) const
		{
			return udph != nullptr;
		}

		bool is_icmpv4(void) const
		{
			return icmpv4h != nullptr;
		}

		bool is_ipcmpv6(void) const
		{
			return icmpv6h != nullptr;
		}

		bool is_valid(void) const
		{
			return is_ipv4() || is_ipv6();
		}

		std::uint8_t ipv4_get_ver(void) const
		{
			return ipv4h->get_ver();
		}

		std::uint8_t ipv4_get_hlen(void) const
		{
			return ipv4h->get_hlen() << 2;
		}

		std::uint8_t ipv4_get_iptos(void) const
		{
			return ipv4h->get_iptos();
		}

		std::uint16_t ipv4_get_iplen(void) const
		{
			return ::ntohs(ipv4h->get_iplen());
		}

		std::uint16_t ipv4_get_ipid(void) const
		{
			return ::ntohs(ipv4h->get_ipid());
		}

		std::uint16_t ipv4_get_ipoffset(void) const
		{
			return ::ntohs(ipv4h->get_ipoffset()) & 0x1fff;
		}

		std::uint8_t ipv4_get_rf(void) const
		{
			return (::ntohs(ipv4h->get_ipoffset()) & 0x8000) >> 15;
		}

		std::uint8_t ipv4_get_df(void) const
		{
			return (::ntohs(ipv4h->get_ipoffset()) & 0x4000) >> 14;
		}

		std::uint8_t ipv4_get_mf(void) const
		{
			return (::ntohs(ipv4h->get_ipoffset()) & 0x2000) >> 13;
		}

		std::uint8_t ipv4_get_ipttl(void) const
		{
			return ipv4h->get_ipttl();
		}

		std::uint8_t ipv4_get_ipproto(void) const
		{
			return ipv4h->get_ipproto();
		}

		void set_ipv4_src_addr(address* addr) const
		{
			addr->family = AF_INET;
			addr->data32[0] = (std::uint32_t)ipv4h->ip_src.s_addr;
			addr->data32[1] = 0;
			addr->data32[2] = 0;
			addr->data32[3] = 0;
		}

		void set_ipv4_dst_addr(address* addr) const
		{
			addr->family = AF_INET;
			addr->data32[0] = (std::uint32_t)ipv4h->ip_dst.s_addr;
			addr->data32[1] = 0;
			addr->data32[2] = 0;
			addr->data32[3] = 0;
		}

		std::int32_t ipv4_get_comp_csum(void) const
		{
			return ipv4vars.comp_csum;
		}

		std::uint16_t ipv4_get_opt_cnt(void) const
		{
			return ipv4vars.opt_cnt;
		}

		std::uint16_t ipv4_get_opts_set(void) const
		{
			return ipv4vars.opts_set;
		}

		std::uint8_t ipv6_get_ver(void) const
		{
			return ipv6h->get_ver();
		}

		std::uint32_t ipv6_get_class(void) const
		{
			return ipv6h->get_class();
		}

		std::uint32_t ipv6_get_flow(void) const
		{
			return ipv6h->get_flow();
		}

		std::uint8_t ipv6_get_nh(void) const
		{
			return ipv6h->get_nh();
		}

		std::uint16_t ipv6_get_plen(void) const
		{
			return ipv6h->get_plen();
		}

		std::uint8_t ipv6_get_hlim(void) const
		{
			return ipv6h->get_hlim();
		}

		std::uint8_t ipv6_get_ip_opts_len(void) const
		{
			return ipv6vars.ip_opts_len;
		}

		std::uint8_t ipv6_get_l4proto(void) const
		{
			return ipv6vars.l4proto;
		}

		std::uint8_t ipv6_get_fh_nh(void) const
		{
			return ipv6eh.get_nh();
		}

		std::uint16_t ipv6_get_fh_offset(void) const
		{
			return ipv6eh.get_offset();
		}

		bool ipv6_get_fh_flag(void) const
		{
			return ipv6eh.get_flag();
		}

		std::uint32_t ipv6_get_fh_id(void) const
		{
			return ipv6eh.get_id();
		}

		void set_ipv6_src_addr(address* addr) const
		{
			addr->family = AF_INET6;
			addr->data32[0] = ipv6h->ip6_src[0];
			addr->data32[1] = ipv6h->ip6_src[1];
			addr->data32[2] = ipv6h->ip6_src[2];
			addr->data32[3] = ipv6h->ip6_src[3];
		}

		void set_ipv6_dst_addr(address* addr) const
		{
			addr->family = AF_INET6;
			addr->data32[0] = ipv6h->ip6_dst[0];
			addr->data32[1] = ipv6h->ip6_dst[1];
			addr->data32[2] = ipv6h->ip6_dst[2];
			addr->data32[3] = ipv6h->ip6_dst[3];
		}

		std::uint8_t tcp_get_offset(void) const
		{
			return tcph->get_offset();
		}

		std::uint8_t tcp_get_hlen(void) const
		{
			return tcph->get_offset() << 2;
		}

		std::uint16_t tcp_get_src_port(void) const
		{
			return tcph->get_src_port();
		}

		std::uint16_t tcp_get_dst_port(void) const
		{
			return tcph->get_dst_port();
		}

		std::uint32_t tcp_get_seq(void) const
		{
			return tcph->get_seq();
		}

		std::uint32_t tcp_get_ack(void) const
		{
			return tcph->get_ack();
		}

		std::uint16_t tcp_get_window(void) const
		{
			return tcph->get_window();
		}

		std::uint16_t tcp_get_sum(void) const
		{
			return tcph->get_sum();
		}

		std::uint16_t tcp_get_urp(void) const
		{
			return tcph->get_urp();
		}

		bool tcp_isset_flag_fin(void) const
		{
			return tcph->isset_flag_fin();
		}

		bool tcp_isset_flag_syn(void) const
		{
			return tcph->isset_flag_syn();
		}

		bool tcp_isset_flag_rst(void) const
		{
			return tcph->isset_flag_rst();
		}

		bool tcp_isset_flag_push(void) const
		{
			return tcph->isset_flag_push();
		}

		bool tcp_isset_flag_ack(void) const
		{
			return tcph->isset_flag_ack();
		}

		bool tcp_isset_flag_urg(void) const
		{
			return tcph->isset_flag_urg();
		}

		std::uint32_t tcp_get_tsval(void) const
		{
			return tcpvars.ts_val;
		}

		std::uint32_t tcp_get_tsecr(void) const
		{
			return tcpvars.ts_ecr;
		}

		bool tcp_has_wscale(void) const
		{
			return tcpvars.ws.type == decode::tcp_opt_ws;
		}

		bool tcp_has_sack(void) const
		{
			return tcpvars.sack.type == decode::tcp_opt_sack;
		}

		bool tcp_has_sackok(void) const
		{
			return tcpvars.sackok.type == decode::tcp_opt_sackok;
		}

		bool tcp_has_ts(void) const
		{
			return tcpvars.ts_set;
		}

		bool tcp_has_mss(void) const
		{
			return tcpvars.mss.type == decode::tcp_opt_mss;
		}

		std::uint8_t tcp_get_wscale(void) const
		{
			return tcp_has_wscale() ? *tcpvars.ws.data <= 14 ?
					*tcpvars.ws.data : 0 : 0;
		}

		int tcp_get_sackok(void) const
		{
			return tcp_has_sackok() ? 1 : 0;
		}

		const std::uint8_t* tcp_get_sack_ptr(void) const
		{
			return tcp_has_sackok() ? tcpvars.ws.data : nullptr;
		}

		int tcp_get_sack_cnt(void) const
		{
			return tcp_has_sackok() ? (tcpvars.sack.len - 2) / 8 : 0;
		}

		std::uint16_t udp_get_len(void) const
		{
			return udph->get_len();
		}

		std::uint16_t udp_get_src_port(void) const
		{
			return udph->get_src_port();
		}

		std::uint16_t udp_get_dst_port(void) const
		{
			return udph->get_dst_port();
		}

		std::uint16_t udp_get_sum(void) const
		{
			return udph->get_sum();
		}

		std::uint8_t icmpv4_get_type(void) const
		{
			return icmpv4h->get_type();
		}

		std::uint8_t icmpv4_get_code(void) const
		{
			return icmpv4h->get_code();
		}

		std::uint16_t icmpv4_get_checksum(void) const
		{
			return icmpv4h->get_checksum();
		}

		std::uint16_t icmpv4_get_id(void) const
		{
			return icmpv4vars.id;
		}
		std::uint16_t icmpv4_get_seq(void) const
		{
			return icmpv4vars.seq;
		}

		const ipv4_hdr* icmpv4_get_emb_ipv4h(void) const
		{
			return icmpv4vars.emb_ipv4h;
		}

		const tcp_hdr* icmpv4_get_emb_tcph(void) const
		{
			return icmpv4vars.emb_tcph;
		}

		const udp_hdr* icmpv4_get_emb_udph(void) const
		{
			return icmpv4vars.emb_udph;
		}
			
		const icmpv4_hdr* icmpv4_get_emb_icmpv4h(void) const
		{
			return icmpv4vars.emb_icmpv4h;
		}

		bool icmpv4_dest_unreach_is_valid(void) const
		{
			return flags & pkt_is_invalid &&
				icmpv4h != nullptr &&
				icmpv4h->get_type() == decode::icmp_dest_unreach &&
				icmpv4vars.emb_ipv4h != nullptr &&
				(icmpv4vars.emb_tcph != nullptr || icmpv4vars.emb_udph != nullptr);
		}

		std::uint8_t icmpv6_get_type(void) const
		{
			return icmpv6h->get_type();
		}

		std::uint8_t icmpv6_get_code(void) const
		{
			return icmpv6h->get_code();
		}

		std::uint16_t icmpv6_get_csum(void) const
		{
			return icmpv6h->get_csum();
		}

		std::uint32_t icmpv6_get_unused(void) const
		{
			return icmpv6h->get_unused();
		}

		std::uint32_t icmpv6_get_error_ptr(void) const
		{
			return icmpv6h->get_error_ptr();
		}

		std::uint32_t icmpv6_get_mtu(void) const
		{
			return icmpv6h->get_mtu();
		}

		std::uint8_t gre_get_ver(void) const
		{
			return greh->get_ver();
		}

		std::uint16_t gre_get_proto(void) const
		{
			return greh->get_proto();
		}

		bool grev1_flag_isset_flags(void) const
		{
			return greh->v1_flag_isset_flags();
		}

		bool grev1_flag_isset_ack(void) const
		{
			return greh->v1_flag_isset_ack();
		}

		bool gre_flag_isset_chksum(void) const
		{
			return greh->flag_isset_chksum();
		}

		bool gre_flag_isset_route(void) const
		{
			return greh->flag_isset_route();
		}

		bool gre_flag_isset_ky(void) const
		{
			return greh->flag_isset_ky();
		}

		bool gre_flag_isset_sq(void) const {
			return greh->flag_isset_sq();
		}

		bool gre_flag_isset_ssr(void) const {
			return greh->flag_isset_ssr();
		}

		bool gre_flag_isset_recur(void) const {
			return greh->flag_isset_recur();
		}

		std::uint16_t sctp_get_src_port(void) const
		{
			return sctph->get_src_port();
		}

		std::uint16_t sctp_get_dst_port(void) const
		{
			return sctph->get_dst_port();
		}

		std::uint16_t vlan_get_id(std::uint8_t layer)
		{
			if (layer > 1)
				return 0;
			if (vlanh[layer] == nullptr && vlan_idx >= (layer + 1))
				return vlan_id[layer];
			return vlanh[layer]->get_id();
		}
	};
}

#endif

#include "pkt.packet.h"
#include "pkt.tcp.h"
#include "pkt.thread_vars.h"

static const std::uint16_t tcp_optlenmax = 40;
static const std::uint16_t tcp_optmax = 20;

void pkt::tcp::set_opts(tcp_opt& dst, const tcp_opt& src)
{
	dst.type = src.type;
	dst.len = src.len;
	dst.data = src.data;
}

bool pkt::tcp::decode_options(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	std::uint8_t opt_cnt = 0;
	tcp_opt opts[tcp_optmax];

	std::uint16_t plen = len;
	while (plen)
	{
		if (*pkt == tcp_opt_eol)
			break;
		else if (*pkt == tcp_opt_nop) {
			pkt++;
			plen--;
		}
		else if (plen < 2)
			break;
		else {
			if (*(pkt + 1) > plen || *(pkt + 1) < 2) {
				p->set_error(tcp_opt_invalid_len);
				return false;
			}
			opts[opt_cnt].type = *pkt;
			opts[opt_cnt].len = *(pkt + 1);
			if (plen > 2)
				opts[opt_cnt].data = (pkt + 2);
			else
				opts[opt_cnt].data = nullptr;
			switch (opts[opt_cnt].type) {
			case tcp_opt_ws:
				if (opts[opt_cnt].len != tcp_opt_ws_len)
					p->set_error(tcp_opt_invalid_len);
				else if (p->tcpvars.ws.type != 0)
					p->set_error(tcp_opt_duplicate);
				else
					set_opts(p->tcpvars.ws, opts[opt_cnt]);
				break;
			case tcp_opt_mss:
				if (opts[opt_cnt].len != tcp_opt_mss_len)
					p->set_error(tcp_opt_invalid_len);
				else if (p->tcpvars.mss.type != 0)
					p->set_error(tcp_opt_duplicate);
				else
					set_opts(p->tcpvars.mss, opts[opt_cnt]);
				break;
			case tcp_opt_sackok:
				if (opts[opt_cnt].len != tcp_opt_sackok_len)
					p->set_error(tcp_opt_invalid_len);
				else if (p->tcpvars.sackok.type != 0)
					p->set_error(tcp_opt_duplicate);
				else
					set_opts(p->tcpvars.sackok, opts[opt_cnt]);
				break;
			case tcp_opt_ts:
				if (opts[opt_cnt].len != tcp_opt_ts_len)
					p->set_error(tcp_opt_invalid_len);
				else if (p->tcpvars.ts_set)
					p->set_error(tcp_opt_duplicate);
				else {
					uint32_t values[2];
					std::memcpy(&values, opts[opt_cnt].data, sizeof(values));
					p->tcpvars.ts_val = ::ntohl(values[0]);
					p->tcpvars.ts_ecr = ::ntohl(values[1]);
					p->tcpvars.ts_set = true;
				}
				break;
			case tcp_opt_sack:
				if (opts[opt_cnt].len < tcp_opt_sack_min_len ||
						opts[opt_cnt].len > tcp_opt_sack_max_len ||
						!((opts[opt_cnt].len - 2) % 8 == 0))
					p->set_error(tcp_opt_invalid_len);
				else if (p->tcpvars.sack.type != 0)
					p->set_error(tcp_opt_duplicate);
				else
					set_opts(p->tcpvars.sack, opts[opt_cnt]);
				break;
			}

			pkt += opts[opt_cnt].len;
			plen -= opts[opt_cnt].len;
			opt_cnt++;
		}
	}

	return true;
}

bool pkt::tcp::decode_packet(const std::shared_ptr<packet>& p,
	const std::uint8_t* pkt, const int& len)
{
	if (len < tcp_header_len) {
		p->set_error(tcp_pkt_too_small);
		return false;
	}

	p->tcph = reinterpret_cast<tcp_hdr *>(const_cast<uint8_t *>(pkt));
	if (p->tcph == nullptr)
		return false;

	std::uint8_t hlen = p->tcp_get_hlen();
	if (len < hlen) {
		p->set_error(tcp_hlen_too_small);
		return false;
	}

	std::uint8_t opt_len = hlen - tcp_header_len;
	if (opt_len > tcp_optlenmax) {
		p->set_error(tcp_invalid_optlen);
		return false;
	}

	if (opt_len > 0)
		decode_options(p, pkt + tcp_header_len, opt_len);

	p->sport = p->tcp_get_src_port();
	p->dport = p->tcp_get_dst_port();

	p->proto = IPPROTO_TCP;

	p->payload = pkt + hlen;
	p->payload_len = len - hlen;

	return true;
}

bool pkt::tcp::decode(const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<packet>& p, const std::uint8_t* pkt,
	const int& len, const std::shared_ptr<packet_queue>& pq)
{
	tv->cc.incr(counter_tcp);

	if (! decode_packet(p, pkt, len)) {
		p->tcph = nullptr;
		return false;
	}

	// p->flow_setup_packet();

	return true;
}

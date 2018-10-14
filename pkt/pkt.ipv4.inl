PKT_INLINE std::uint8_t pkt::ipv4_hdr::get_ver(void) const
{
	return (ip_verhl & 0xf0) >> 4;
}

PKT_INLINE std::uint8_t pkt::ipv4_hdr::get_hlen(void) const
{
	return ip_verhl & 0x0f;
}

PKT_INLINE std::uint8_t pkt::ipv4_hdr::get_iptos(void) const
{
	return ip_tos;
}

PKT_INLINE std::uint16_t pkt::ipv4_hdr::get_iplen(void) const
{
	return ip_len;
}

PKT_INLINE std::uint16_t pkt::ipv4_hdr::get_ipid(void) const
{
	return ip_id;
}

PKT_INLINE std::uint16_t pkt::ipv4_hdr::get_ipoffset(void) const
{
	return ip_off;
}

PKT_INLINE std::uint8_t pkt::ipv4_hdr::get_ipttl(void) const
{
	return ip_ttl;
}

PKT_INLINE std::uint8_t pkt::ipv4_hdr::get_ipproto(void) const
{
	return ip_proto;
}

PKT_INLINE struct ::in_addr pkt::ipv4_hdr::get_ipsrc(void) const
{
	return ip_src;
}

PKT_INLINE struct ::in_addr pkt::ipv4_hdr::get_ipdst(void) const
{
	return ip_dst;
}

PKT_INLINE pkt::ipv4_opt::ipv4_opt()
{
	std::memset(this, 0, sizeof(ipv4_opt));
}

PKT_INLINE pkt::ipv4_options::ipv4_options()
{
	std::memset(this, 0, sizeof(ipv4_options));
}

PKT_INLINE pkt::ipv4_vars::ipv4_vars()
{
	std::memset(this, 0, sizeof(ipv4_vars));
}

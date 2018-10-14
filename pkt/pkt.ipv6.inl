PKT_INLINE std::uint8_t pkt::ipv6_hdr::get_ver(void) const
{
	return (ip6_vfc & 0xf0) >> 4;
}

PKT_INLINE std::uint32_t pkt::ipv6_hdr::get_class(void) const
{
	return (ip6_flow & 0x0ff00000) >> 20;
}

PKT_INLINE std::uint32_t pkt::ipv6_hdr::get_flow(void) const
{
	return (ip6_flow & 0x000fffff);
}

PKT_INLINE std::uint8_t pkt::ipv6_hdr::get_nh(void) const
{
	return ip6_nxt;
}

PKT_INLINE std::uint16_t pkt::ipv6_hdr::get_plen(void) const
{
	return ::ntohs(ip6_plen);
}

PKT_INLINE std::uint8_t pkt::ipv6_hdr::get_hlim(void) const
{
	return ip6_hlim;
}

PKT_INLINE std::uint8_t pkt::ipv6_ext_hdrs::get_nh(void) const
{
	return fh_nh;
}

PKT_INLINE std::uint16_t pkt::ipv6_ext_hdrs::get_offset(void) const
{
	return fh_offset;
}

PKT_INLINE bool pkt::ipv6_ext_hdrs::get_flag(void) const
{
	return fh_more_frags_set;
}

PKT_INLINE std::uint32_t pkt::ipv6_ext_hdrs::get_id(void) const
{
	return fh_id;
}

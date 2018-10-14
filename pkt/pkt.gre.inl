PKT_INLINE std::uint8_t pkt::gre_hdr::get_ver(void) const
{
	return (version & 0x07) != 0;
}

PKT_INLINE std::uint16_t pkt::gre_hdr::get_proto(void) const
{
	return ::ntohs(ether_type);
}

PKT_INLINE std::uint8_t pkt::gre_hdr::get_flags(void) const
{
	return (version & 0xF8) != 0;
}

PKT_INLINE bool pkt::gre_hdr::v1_flag_isset_flags(void) const
{
	return (version & 0x78) != 0;
}

PKT_INLINE bool pkt::gre_hdr::v1_flag_isset_ack(void) const
{
	return (version & 0x80) != 0;
}

PKT_INLINE bool pkt::gre_hdr::flag_isset_chksum(void) const
{
	return (flags & 0x80) != 0;
}

PKT_INLINE bool pkt::gre_hdr::flag_isset_route(void) const
{
	return (flags & 0x40) != 0;
}

PKT_INLINE bool pkt::gre_hdr::flag_isset_ky(void) const
{
	return (flags & 0x20) != 0;
}

PKT_INLINE bool pkt::gre_hdr::flag_isset_sq(void) const
{
	return (flags & 0x10) != 0;
}

PKT_INLINE bool pkt::gre_hdr::flag_isset_ssr(void) const
{
	return (flags & 0x08) != 0;
}

PKT_INLINE bool pkt::gre_hdr::flag_isset_recur(void) const
{
	return (flags & 0x07) != 0;
}

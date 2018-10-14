PKT_INLINE std::uint8_t pkt::icmpv4_hdr::get_type(void) const
{
	return ic_type;
}

PKT_INLINE std::uint8_t pkt::icmpv4_hdr::get_code(void) const
{
	return ic_code;
}

PKT_INLINE std::uint16_t pkt::icmpv4_hdr::get_checksum(void) const
{
	return ::ntohs(ic_checksum);
}

PKT_INLINE pkt::icmpv4_vars::icmpv4_vars()
{
	std::memset(this, 0, sizeof(icmpv4_vars));
}
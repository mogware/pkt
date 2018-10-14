PKT_INLINE std::uint8_t pkt::icmpv6_hdr::get_type(void) const
{
	return ic_type;
}

PKT_INLINE std::uint8_t pkt::icmpv6_hdr::get_code(void) const
{
	return ic_code;
}

PKT_INLINE std::uint16_t pkt::icmpv6_hdr::get_csum(void) const
{
	return ::ntohs(ic_csum);
}

PKT_INLINE std::uint32_t pkt::icmpv6_hdr::get_unused(void) const
{
	return ic_unused;
}

PKT_INLINE std::uint32_t pkt::icmpv6_hdr::get_error_ptr(void) const
{
	return ic_error_ptr;
}

PKT_INLINE std::uint32_t pkt::icmpv6_hdr::get_mtu(void) const
{
	return ic_mtu;
}

PKT_INLINE pkt::icmpv6_vars::icmpv6_vars()
{
	std::memset(this, 0, sizeof(icmpv6_vars));
}

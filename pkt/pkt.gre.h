#ifndef __PKT_GRE__
#define __PKT_GRE__

#include "pkt.decode.h"

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	PACKED(
	struct gre_hdr
	{
		std::uint8_t flags;
		std::uint8_t version;
		std::uint16_t ether_type;

		PKT_INLINE std::uint8_t get_ver(void) const;
		PKT_INLINE std::uint16_t get_proto(void) const;
		PKT_INLINE std::uint8_t get_flags(void) const;
		PKT_INLINE bool v1_flag_isset_flags(void) const;
		PKT_INLINE bool v1_flag_isset_ack(void) const;
		PKT_INLINE bool flag_isset_chksum(void) const;
		PKT_INLINE bool flag_isset_route(void) const;
		PKT_INLINE bool flag_isset_ky(void) const;
		PKT_INLINE bool flag_isset_sq(void) const;
		PKT_INLINE bool flag_isset_ssr(void) const;
		PKT_INLINE bool flag_isset_recur(void) const;
	});

	PACKED(
	struct gre_sre_hdr
	{
		std::uint16_t af;
		std::uint8_t sre_offset;
		std::uint8_t sre_length;
	});

	class gre : public decode
	{
	public:
		static bool decode(const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::uint8_t* pkt, const int& len,
			const std::shared_ptr<packet_queue>& pq);
	};
}

#if defined(__PKT_INLINE__)
#include "pkt.gre.inl"
#endif

#endif


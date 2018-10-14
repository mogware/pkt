#ifndef __PKT_DEFRAG_TRACKER__
#define __PKT_DEFRAG_TRACKER__

#include "pkt.noncopyable.h"

#include <cstdint>
#include <memory>

namespace pkt
{
	struct packet;
	struct thread_vars;
	class packet_queue;

	struct frag
	{
		std::uint16_t offset;			// offset of fragment
		std::uint16_t len;				// length of fragment
		std::uint8_t hlen;				// length of fragments IP header
		bool more_frags;				// more fragments?
		bool skip;						// skip fragment during re-assembly
		std::uint16_t ip_hdr_offset;	// offset where IP header starts
		std::uint16_t frag_hdr_offset;	// offset where the frag header starts
		std::uint16_t data_offset;		// offset to packet data
		std::uint16_t data_len;			// length of data
		std::uint16_t ltrim;			// number of leading bytes to trim
		const uint8_t *pkt;				// the actual packet
	};

	class defrag_tracker : private noncopyable
	{
	public:
		std::shared_ptr<packet> insert_frag(
			const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p,
			const std::shared_ptr<packet_queue>& pq);
		std::shared_ptr<packet> ipv4_reassemble(
			const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p);
		std::shared_ptr<packet> ipv6_reassemble(
			const std::shared_ptr<thread_vars>& tv,
			const std::shared_ptr<packet>& p);
	public:
		void release(void);
	public:
		static std::shared_ptr<defrag_tracker> create(void);
	};
}

#endif

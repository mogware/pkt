#ifndef __PKT_DEFRAG_TRACKER_MAP__
#define __PKT_DEFRAG_TRACKER_MAP__

#include "pkt.noncopyable.h"

#include <memory>
#include <cstdint>
#include <unordered_map>
#include <queue>

namespace pkt
{
	struct packet;
	class defrag_tracker;

	class packet_key
	{
		union {
			struct {
				std::uint32_t src_[4], dst_[4];
				std::uint32_t id_;
				std::uint16_t vlan_id_[2];
				std::uint8_t proto_;
			};
			std::uint32_t u32_[11];
		};
	public:
		packet_key(void);
	public:
		static std::shared_ptr<packet_key> create(void);
	friend class packet_key_hash;
	friend struct packet_key_equal;
	};

	class packet_key_hash
	{
		int rand_;
	public:
		packet_key_hash(void);
	public:
		std::size_t operator()(
			const std::shared_ptr<packet_key>& key) const;
	private:
		static std::size_t hashword(const std::uint32_t* k,
			const int& len, const std::uint32_t& initval);
	};

	struct packet_key_equal
	{
		bool operator()(const std::shared_ptr<packet_key>& lhs,
			const std::shared_ptr<packet_key>& rhs) const;
	};

	class defrag_tracker_map : private noncopyable
	{
		std::unordered_map<
			std::shared_ptr<packet_key>,
			std::shared_ptr<defrag_tracker>,
			packet_key_hash, packet_key_equal> map_;
		std::queue<std::shared_ptr<defrag_tracker>> que_;
	public:
		std::shared_ptr<defrag_tracker>
			get_tracker(const std::shared_ptr<packet>& p);
		void move_tracker_to_spare(const std::shared_ptr<defrag_tracker>& dt);
	public:
		static std::shared_ptr<packet_key>
			get_packet_key(const std::shared_ptr<packet>& p);
	private:
		std::shared_ptr<defrag_tracker>
			get_new(const std::shared_ptr<packet>& p);
		std::shared_ptr<defrag_tracker> deque(void);
	};
}

#endif

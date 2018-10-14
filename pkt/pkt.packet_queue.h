#ifndef __PKT_PACKET_QUEUE__
#define __PKT_PACKET_QUEUE__

#include "pkt.noncopyable.h"

#include <memory>
#include <queue>

namespace pkt
{
	struct packet;

	class packet_queue : private noncopyable
	{
		std::queue<std::shared_ptr<packet>> que_;
	public:
		static std::shared_ptr<packet_queue> create()
		{
			return std::make_shared<packet_queue>();
		}
	public:
		void enque(std::shared_ptr<packet>& p)
		{
			que_.push(std::move(p));
		}
		std::shared_ptr<packet> deque(void)
		{
			if (que_.empty())
				return nullptr;
			std::shared_ptr<packet> p = std::move(que_.front());
			que_.pop();
			return p;
		}
	};
}

#endif


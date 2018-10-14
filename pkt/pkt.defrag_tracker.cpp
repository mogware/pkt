#include "pkt.packet.h"
#include "pkt.defrag_tracker.h"

std::shared_ptr<pkt::packet> pkt::defrag_tracker::insert_frag(
	const std::shared_ptr<pkt::thread_vars>& tv,
	const std::shared_ptr<pkt::packet>& p,
	const std::shared_ptr<pkt::packet_queue>& pq)
{
	printf("insert fragment\n");
	return nullptr;
}

void pkt::defrag_tracker::release(void)
{
}

std::shared_ptr<pkt::defrag_tracker> pkt::defrag_tracker::create(void)
{
	return std::make_shared<defrag_tracker>();
}

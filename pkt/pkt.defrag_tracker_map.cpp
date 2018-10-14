#include <functional>
#include <cstdlib>
#include <ctime>

#include "pkt.packet.h"
#include "pkt.defrag_tracker.h"
#include "pkt.defrag_tracker_map.h"

static int u32cmp(const std::uint32_t* a, const std::uint32_t* b, const int& n)
{
	for (int i = 0; i < n; i++)
	{
		if (a[i] > b[i])
			return 1;
		if (a[i] < b[i])
			return -1;
	}
	return 0;
}

pkt::packet_key::packet_key(void)
{
	std::memset(this, 0, sizeof(packet_key));
}

std::shared_ptr<pkt::packet_key> pkt::packet_key::create(void)
{
	return std::make_shared<packet_key>();
}

pkt::packet_key_hash::packet_key_hash(void)
{
	std::srand(static_cast<unsigned>(std::time(0)));
	rand_ = std::rand();
}

std::size_t pkt::packet_key_hash::operator()(
	const std::shared_ptr<pkt::packet_key>& key) const
{
	return hashword(key->u32_, 11, rand_);
}

std::size_t pkt::packet_key_hash::hashword(const std::uint32_t* k,
	const int& len, const std::uint32_t& initval)
{
	std::size_t h = initval;
	for (int i = 0; i < len; ++i)
		h ^= std::hash<std::size_t>{}(k[i]) + 0x9e3779b9 + (h << 6) + (h >> 2);
	return h;
}

bool pkt::packet_key_equal::operator()(
	const std::shared_ptr<pkt::packet_key>& lhs,
	const std::shared_ptr<pkt::packet_key>& rhs) const
{
	return u32cmp(lhs->u32_, rhs->u32_, 11) == 0;
}

std::shared_ptr<pkt::defrag_tracker> pkt::defrag_tracker_map::get_tracker(
	const std::shared_ptr<pkt::packet>& p)
{
	std::shared_ptr<packet_key> key = get_packet_key(p);
	auto it = map_.find(key);
	if (it != map_.end())
		return it->second;
	std::shared_ptr<defrag_tracker> dt(get_new(p));
	map_.emplace(std::move(key), dt);
	return dt;
}

void pkt::defrag_tracker_map::move_tracker_to_spare(
	const std::shared_ptr<pkt::defrag_tracker>& dt)
{
	que_.push(dt);
}

std::shared_ptr<pkt::defrag_tracker> pkt::defrag_tracker_map::deque(void)
{
	if (que_.empty())
		return nullptr;
	std::shared_ptr<defrag_tracker> dt = que_.front();
	que_.pop();
	return dt;
}

std::shared_ptr<pkt::defrag_tracker> pkt::defrag_tracker_map::get_new(
	const std::shared_ptr<packet>& p)
{
	std::shared_ptr<pkt::defrag_tracker> dt = deque();
	if (dt == nullptr)
		return defrag_tracker::create();
	return dt;
}

std::shared_ptr<pkt::packet_key> pkt::defrag_tracker_map::get_packet_key(
	const std::shared_ptr<pkt::packet>& p)
{
	std::shared_ptr<packet_key> key(packet_key::create());
	if (p->is_ipv4())
	{
		if (p->src.data32[0] > p->dst.data32[0]) {
			key->src_[0] = p->src.data32[0];
			key->dst_[0] = p->dst.data32[0];
		}
		else {
			key->src_[0] = p->dst.data32[0];
			key->dst_[0] = p->src.data32[0];
		}
		key->id_ = (std::uint32_t)p->ipv4_get_ipid();
	}
	else if (p->is_ipv6())
	{
		if (u32cmp(p->src.data32, p->dst.data32, 4) > 0) {
			key->src_[0] = p->src.data32[0];
			key->src_[1] = p->src.data32[1];
			key->src_[2] = p->src.data32[2];
			key->src_[3] = p->src.data32[3];
			key->dst_[0] = p->dst.data32[0];
			key->dst_[1] = p->dst.data32[1];
			key->dst_[2] = p->dst.data32[2];
			key->dst_[3] = p->dst.data32[3];
		}
		else
		{
			key->src_[0] = p->dst.data32[0];
			key->src_[1] = p->dst.data32[1];
			key->src_[2] = p->dst.data32[2];
			key->src_[3] = p->dst.data32[3];
			key->dst_[0] = p->src.data32[0];
			key->dst_[1] = p->src.data32[1];
			key->dst_[2] = p->src.data32[2];
			key->dst_[3] = p->src.data32[3];
		}
		key->id_ = p->ipv6_get_fh_id();
	}
	key->vlan_id_[0] = p->vlan_id[0];
	key->vlan_id_[1] = p->vlan_id[1];
	key->proto_ = p->proto;

	return key;
}

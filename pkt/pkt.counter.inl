PKT_INLINE void pkt::counter_context::incr(const int& id)
{
	std::lock_guard<std::mutex> lock(mutex_);
	counters_[id]->value_++;
	counters_[id]->updates_++;
}

PKT_INLINE void pkt::counter_context::add(const int& id, const std::uint64_t& v)
{
	std::lock_guard<std::mutex> lock(mutex_);
	counters_[id]->value_ += v;
	counters_[id]->updates_++;
}

PKT_INLINE void pkt::counter_context::set(const int& id, const std::uint64_t& v)
{
	std::lock_guard<std::mutex> lock(mutex_);
	counters_[id]->value_ = v;
	counters_[id]->updates_++;
}

PKT_INLINE std::uint64_t pkt::counter_context::get(const int& id)
{
	std::lock_guard<std::mutex> lock(mutex_);
	return counters_[id]->value_;
}

PKT_INLINE const std::string& pkt::counter_context::name(const int& id)
{
	return counters_[id]->name_;
}

#ifndef __PKT_NONCOPYABLE__
#define __PKT_NONCOPYABLE__

namespace pkt
{
	class noncopyable
	{
	protected:
		constexpr noncopyable() = default;
		~noncopyable() = default;
	protected:
		noncopyable(const noncopyable&) = delete;
		noncopyable(noncopyable&&) = delete;
	protected:
		noncopyable& operator=(const noncopyable&) = delete;
		noncopyable& operator=(noncopyable&&) = delete;
	};
}

#endif

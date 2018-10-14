#ifndef __PKT_THREAD_VARS__
#define __PKT_THREAD_VARS__

#include "pkt.counter.h"
#include "pkt.noncopyable.h"

#include <memory>

namespace pkt
{
	struct thread_vars : private noncopyable
	{
		counter_context cc;

		static std::shared_ptr<thread_vars> create()
		{
			return std::make_shared<thread_vars>();
		}
	};
}

#endif

#ifndef EDGE_DISPATCH_H
#define EDGE_DISPATCH_H

#include "keystone.h"
#include "edge_common.h"
#include "edge_call.h"

namespace Keystone {

typedef int (*edgecallwrapper)(Enclave*, void*, struct shared_region*);

class EdgeCallDispatcher {
	protected:
		struct shared_region shared_region;
	public:
		void setupSharedRegion(uintptr_t shared_start, size_t shared_size){
			shared_region_init(shared_start, shared_size, &shared_region);			
		}
		virtual int dispatch(Enclave* enclave, void* buffer) = 0;
		virtual int dispatchBlocked(Enclave* enclave, void* buffer) = 0;
};

class DefaultEdgeCallDispatcher : public EdgeCallDispatcher {
	private:
		edgecallwrapper edge_call_table[MAX_EDGE_CALL];
		edgecallwrapper edge_call_blocked_table[MAX_EDGE_CALL];
	public:
		int register_call(unsigned long call_id, edgecallwrapper func, edgecallwrapper blocked_handler);
		int dispatch(Enclave* enclave, void* buffer);
		int dispatchBlocked(Enclave* enclave, void* buffer);
};

} // namespace Keystone
#endif

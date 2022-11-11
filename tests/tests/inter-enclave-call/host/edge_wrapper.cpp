//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "edge_wrapper.h"
#include "edge_call.h"
#include "edge_dispatch.h"
#include "report.h"
#include "keystone.h"
#include <string.h>
/* Really all of this file should be autogenerated, that will happen
   eventually. */

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_COPY_REPORT 3
#define OCALL_GET_STRING 4
#define OCALL_GET_OTHER_ENCLAVE 5
#define ENCLAVE_MAX_COUNT 8

Keystone* enclaves[ENCLAVE_MAX_COUNT]; 
int enclave_n;

int edge_init(Keystone* enclave, DefaultEdgeCallDispatcher* dispatcher){
  enclave->registerOcallDispatch(dispatcher);
  dispatcher->register_call(OCALL_PRINT_BUFFER, print_buffer_wrapper, NULL);
  dispatcher->register_call(OCALL_PRINT_VALUE, print_value_wrapper, NULL);
  dispatcher->register_call(OCALL_COPY_REPORT, copy_report_wrapper, NULL);
  dispatcher->register_call(OCALL_GET_STRING, get_host_string_wrapper, NULL);
  dispatcher->register_call(OCALL_GET_OTHER_ENCLAVE, get_other_enclave_wrapper, NULL);
  return 0;
}

int print_buffer_wrapper(int eid, void* buffer, struct shared_region* shared_region)
{
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t arg_len;
  if(edge_call_args_ptr(edge_call, &call_args, &arg_len, shared_region) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return 0;
  }

  ret_val = print_buffer(eid, (char*)call_args);

  // We are done with the data section for args, use as return region
  // TODO safety check?
  uintptr_t data_section = edge_call_data_ptr(shared_region);

  memcpy((void*)data_section, &ret_val, sizeof(unsigned long));

  if( edge_call_setup_ret(edge_call, (void*) data_section, sizeof(unsigned long), shared_region)){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return 0;

}

int print_value_wrapper(int eid, void* buffer, struct shared_region* shared_region)
{
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len, shared_region) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return 0;
  }

  print_value(eid, *(unsigned long*)call_args);

  edge_call->return_data.call_status = CALL_STATUS_OK;
  return 0;
}

int copy_report_wrapper(int eid, void* buffer, struct shared_region* shared_region)
{

  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t data_section;
  unsigned long ret_val;
  //TODO check the other side of this
  if(edge_call_get_ptr_from_offset(edge_call->call_arg_offset, sizeof(report_t),
				   &data_section, shared_region) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return 0;
  }

  copy_report((void*)data_section);

  edge_call->return_data.call_status = CALL_STATUS_OK;

  return 0;
}

int get_host_string_wrapper(int eid, void* buffer, struct shared_region* shared_region)
{
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len, shared_region) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return 0;
  }

  const char* host_str = get_host_string();
  size_t host_str_len = strlen(host_str)+1;

  // This handles wrapping the data into an edge_data_t and storing it
  // in the shared region.
  if( edge_call_setup_wrapped_ret(edge_call, (void*)host_str, host_str_len, shared_region)){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return 0;
}

int get_other_enclave_wrapper(int eid, void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;
	int i;
	for(i = 0; i < enclave_n; i ++){
		if(enclaves[i]->getID() != eid){
			break;
		}
	}
	if(i >= enclave_n){
		edge_call->return_data.call_status = CALL_STATUS_ERROR;
	} else{
		uintptr_t data_section = edge_call_data_ptr(shared_region);
		int sid = enclaves[i]->getSID();
		memcpy((void*)data_section, &sid, sizeof(sid));
		if(edge_call_setup_ret(edge_call,
				   	(void*)data_section, sizeof(sid), shared_region)){
			edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
		} else{
			edge_call->return_data.call_status = CALL_STATUS_OK;
		}
	}
return 0;
}

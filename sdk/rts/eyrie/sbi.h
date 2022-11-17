//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SBI_H_
#define __SBI_H_

#include <stdint.h>
#include "common.h"
#include "rpc.h"
#include "performance.h"
#include "rt_stats.h"

#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1
#define SBI_CONSOLE_GETCHAR 2

#define SBI_SM_CREATE_ENCLAVE             2001
#define SBI_SM_DESTROY_ENCLAVE            2002
#define SBI_SM_ATTEST_ENCLAVE             3002
#define SBI_SM_RUN_ENCLAVE                2003
#define SBI_SM_STOP_ENCLAVE               3004
#define SBI_SM_RESUME_ENCLAVE             2005
#define SBI_SM_RANDOM                     3001
#define SBI_SM_ELASTICLAVE_CREATE	      2009
#define SBI_SM_ELASTICLAVE_CHANGE		  2008
#define SBI_SM_ELASTICLAVE_MAP		      2010
#define SBI_SM_ELASTICLAVE_SHARE	      2014
#define SBI_SM_ELASTICLAVE_UNMAP		  2011
#define SBI_SM_ELASTICLAVE_TRANSFER		  2013
#define SBI_SM_ELASTICLAVE_DESTROY		  2012
#define SBI_SM_ELASTICLAVE_REGION_EVENTS  2015
#define SBI_SM_EXIT_ENCLAVE               3006
#define SBI_SM_CALL_PLUGIN                4000

/* Plugin IDs and Call IDs */
#define SM_MULTIMEM_PLUGIN_ID   0x01
#define SM_MULTIMEM_CALL_GET_SIZE 0x01
#define SM_MULTIMEM_CALL_GET_ADDR 0x02

#define SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE 0x08424b45

#define SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3, ___arg4) ({\
	uintptr_t __res; \
	if(___which != SBI_SM_EXIT_ENCLAVE) \
		performance_check_start(&stats.stats_sbi); \
	asm volatile (\
		"mv a0, %1\n\t" \
		"mv a1, %2\n\t" \
		"mv a2, %3\n\t" \
		"mv a3, %4\n\t" \
		"mv a4, %5\n\t" \
		"mv a7, %6\n\t" \
		"ecall\n\t" \
		"mv %0, a0" : "=r" (__res) : "r" (___arg0) , "r" (___arg1) , "r" (___arg2) , "r" (___arg3), "r" (___arg4), "r" (___which) : \
		"a0", "a1", "a2", "a3", "a4", "a7", "memory"\
	); \
	performance_check_end(&stats.stats_sbi); \
	performance_count(&stats.stats_sbi); \
	__res; })



/* Lazy implementations until SBI is finalized */
#define SBI_CALL_0(___ext, ___which) SBI_CALL(___ext, ___which, 0, 0, 0, 0, 0)
#define SBI_CALL_1(___ext, ___which, ___arg0) SBI_CALL(___ext, ___which, ___arg0, 0, 0, 0, 0)
#define SBI_CALL_2(___ext, ___which, ___arg0, ___arg1) SBI_CALL(___ext, ___which, ___arg0, ___arg1, 0, 0, 0)
#define SBI_CALL_3(___ext, ___which, ___arg0, ___arg1, ___arg2) SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2, 0, 0)
#define SBI_CALL_4(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3) SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3, 0)
#define SBI_CALL_5(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3, ___arg4) SBI_CALL(___ext, ___which, ___arg0, ___arg1, ___arg2, ___arg3, ___arg4)


static inline void sbi_set_timer(uint64_t stime_value){
#if __riscv_xlen == 32
	SBI_CALL_2(SBI_SET_TIMER, 0, stime_value, stime_value >> 32);
#else
	SBI_CALL_1(SBI_SET_TIMER, 0, stime_value);
#endif
}

static inline uintptr_t sbi_stop_enclave(uint64_t request)
{
  return SBI_CALL_1(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_STOP_ENCLAVE, request);
}

static inline void sbi_exit_enclave(uint64_t retval, uintptr_t stats_pa)
{
#ifdef VSHMEM_ENABLED
  //rpc_quit();
#endif
  SBI_CALL_2(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_EXIT_ENCLAVE, retval, stats_pa);
}

static inline uintptr_t sbi_random()
{
  return SBI_CALL_0(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_RANDOM);
}

static inline uintptr_t sbi_query_multimem(size_t *size)
{
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_CALL_PLUGIN, SM_MULTIMEM_PLUGIN_ID, SM_MULTIMEM_CALL_GET_SIZE, size);
}

static inline uintptr_t sbi_query_multimem_addr(uintptr_t *addr)
{
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_CALL_PLUGIN, SM_MULTIMEM_PLUGIN_ID, SM_MULTIMEM_CALL_GET_ADDR, addr);
}

static inline uintptr_t sbi_attest_enclave(void* report, void* buf, uintptr_t len)
{
  return SBI_CALL_3(SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE, SBI_SM_ATTEST_ENCLAVE, report, buf, len);
}
#endif

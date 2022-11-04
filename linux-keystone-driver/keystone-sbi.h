//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_SBI_
#define _KEYSTONE_SBI_

#include "keystone_user.h"
#include <asm/sbi.h>

#define KEYSTONE_SBI_EXT_ID  0x08424b45

#define REGION_MODE_R 1
#define REGION_MODE_W 2

#define SBI_SM_CREATE_ENCLAVE        2001
#define SBI_SM_DESTROY_ENCLAVE       2002
#define SBI_SM_RUN_ENCLAVE           2003
#define SBI_SM_RESUME_ENCLAVE        2005
#define SBI_SM_PRINT_STATS           2006
#define SBI_SM_PRINT_RT_STATS        2007
#define SBI_SM_ELASTICLAVE_CHANGE    2008
#define SBI_SM_ELASTICLAVE_CREATE    2009
#define SBI_SM_ELASTICLAVE_MAP       2010
#define SBI_SM_ELASTICLAVE_UNMAP     2011
#define SBI_SM_ELASTICLAVE_DESTROY   2012
#define SBI_SM_ELASTICLAVE_TRANSFER  2013
#define SBI_SM_ELASTICLAVE_SHARE     2014

/* needed?
#define SBI_SM_STOP_ENCLAVE     106
#define SBI_SM_SHGET			111
#define SBI_SM_REGION_OPEN		112
#define SBI_SM_ELASTICLAVE_REGION_EVENTS 122
*/

struct keystone_sbi_pregion_t
{
  uintptr_t paddr;
  size_t size;
  unsigned long mode;
};

struct keystone_sbi_create_t
{
  // Memory regions for the enclave
  struct keystone_sbi_pregion_t epm_region;
  struct keystone_sbi_pregion_t utm_region;

  // physical addresses
  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;

  // Parameters
  struct runtime_params_t params;

  // Outputs from the creation process
  unsigned int* eid_pptr;
};

struct sbiret sbi_sm_create_enclave(struct keystone_sbi_create_t* args);
struct sbiret sbi_sm_destroy_enclave(unsigned long eid, unsigned long enclave_shm_list);
struct sbiret sbi_sm_run_enclave(unsigned long eid, unsigned long request_args);
struct sbiret sbi_sm_resume_enclave(unsigned long eid, unsigned long request_args, uintptr_t resp0, uintptr_t resp1);
struct sbiret sbi_sm_print_stats(unsigned long eid, uintptr_t tmp_stats_paddr);
struct sbiret sbi_sm_print_rt_stats(unsigned long eid, uintptr_t tmp_stats_paddr);
struct sbiret sbi_sm_elasticlave_change(__u64 uid, __u64 perm);
struct sbiret sbi_sm_elasticlave_create(uintptr_t pa, __u64 size, unsigned long uid);
struct sbiret sbi_sm_elasticlave_map(uid_t uid, uintptr_t pa_addr, uintptr_t pa_size);
struct sbiret sbi_sm_elasticlave_unmap(uintptr_t mem_mappings_uid);
struct sbiret sbi_sm_elasticlave_destroy(uid_t uid);
struct sbiret sbi_sm_elasticlave_transfer(uintptr_t uid, uintptr_t eid);
struct sbiret sbi_sm_elasticlave_share(uintptr_t uid, uintptr_t eid, uintptr_t perm);

#endif

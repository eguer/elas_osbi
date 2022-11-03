//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_SBI_H_
#define _KEYSTONE_SBI_H_

#include <sbi/sbi_types.h>
#include <sbi/sbi_trap.h>

#define SM_REQUEST_ELASTICLAVE_CREATE   1000
#define SM_REQUEST_ELASTICLAVE_DESTROY  1001

unsigned long
sbi_sm_create_enclave(unsigned long *out_val, uintptr_t create_args);

unsigned long
sbi_sm_destroy_enclave(unsigned long eid);

unsigned long
sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid);

unsigned long
sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval);

unsigned long
sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request);

unsigned long
sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid);

unsigned long
sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size);

unsigned long
sbi_sm_print_stats(unsigned long eid, uintptr_t tmp_stats_paddr);

unsigned long
sbi_sm_print_rt_stats(unsigned long eid, uintptr_t tmp_stats_paddr);

unsigned long
sbi_sm_elasticlave_change(unsigned int uid, unsigned long perm);

unsigned long
sbi_sm_elasticlave_create(uintptr_t pa, unsigned long size, unsigned long uid);

unsigned long 
sbi_sm_elasticlave_host_create(uintptr_t pa, uintptr_t size, uintptr_t uid_ret);

unsigned long
sbi_sm_elasticlave_map(unsigned int uid, uintptr_t pa_addr, uintptr_t pa_size);

unsigned long 
sbi_sm_elasticlave_unmap(uintptr_t mem_mappings_uid);

unsigned long
sbi_sm_elasticlave_destroy(unsigned int uid);

unsigned long
sbi_sm_elasticlave_transfer(uintptr_t uid, uintptr_t eid);

unsigned long
sbi_sm_elasticlave_share(uintptr_t uid, uintptr_t eid, uintptr_t perm);

unsigned long
sbi_sm_elasticlave_region_events(uintptr_t event_buf, uintptr_t count_ptr, uintptr_t count_lim); ///////

unsigned long
sbi_sm_elasticlave_install_regev(uintptr_t regev_notify);

// unsigned long
// sbi_sm_get_sealing_key(uintptr_t seal_key, uintptr_t key_ident, size_t key_ident_size);

unsigned long
sbi_sm_random();

unsigned long
sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1);

#endif

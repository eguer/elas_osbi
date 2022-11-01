//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include "plugins/plugins.h"
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>

extern struct enclave enclaves[];
extern spinlock_t encl_lock;

unsigned long sbi_sm_create_enclave(unsigned long* eid, uintptr_t create_args)
{
  struct keystone_sbi_create create_args_local;
  unsigned long ret;

  ret = copy_enclave_create_args(create_args, &create_args_local);

  if (ret)
    return ret;

  ret = create_enclave(eid, create_args_local);
  return ret;
}

unsigned long sbi_sm_destroy_enclave(unsigned long eid)
{
  unsigned long ret;
  ret = destroy_enclave((unsigned int)eid);
  return ret;
}

unsigned long sbi_sm_run_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  regs->a0 = run_enclave(regs, (unsigned int) eid);
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_resume_enclave(struct sbi_trap_regs *regs, unsigned long eid)
{
  unsigned long ret;
  ret = resume_enclave(regs, (unsigned int) eid);
  if (!regs->zero)
    regs->a0 = ret;
  regs->mepc += 4;

  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_exit_enclave(struct sbi_trap_regs *regs, unsigned long retval)
{
  regs->a0 = exit_enclave(regs, cpu_get_enclave_id());
  regs->a1 = retval;
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_stop_enclave(struct sbi_trap_regs *regs, unsigned long request)
{
  regs->a0 = stop_enclave(regs, request, cpu_get_enclave_id());
  regs->mepc += 4;
  sbi_trap_exit(regs);
  return 0;
}

unsigned long sbi_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size)
{
  unsigned long ret;
  ret = attest_enclave(report, data, size, cpu_get_enclave_id());
  return ret;
}

// TODO clean up?
// unsigned long sbi_sm_get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
//                        size_t key_ident_size)
// {
//   unsigned long ret;
//   ret = get_sealing_key(sealing_key, key_ident, key_ident_size,
//                          cpu_get_enclave_id());
//   return ret;
// }

unsigned long sbi_sm_random()
{
  return (unsigned long) platform_random();
}

unsigned long sbi_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
  unsigned long ret;
  ret = call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
  return ret;
}

unsigned long sbi_sm_print_stats(unsigned long eid, uintptr_t tmp_stats_paddr) {
	if (cpu_is_enclave_context()) {
		return SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;
	}

	struct enclave* encl = encl_get(eid);
	copy_to_host(ret_ptr, &encl->stats, sizeof(struct enclave_stats));
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long sbi_sm_print_rt_stats(unsigned long eid, uintptr_t tmp_stats_paddr) {
	if(cpu_is_enclave_context()) {
		return SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;
	}

	struct enclave* encl = encl_get(eid);
	copy_to_host(ret_ptr, &encl->rt_stats, sizeof(struct enclave_rt_stats));
	return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long sbi_sm_elasticlave_change(__u64 uid, __u64 perm) {
	enclave_id eid = cpu_is_enclave_context() ? cpu_get_enclave_id() : EID_UNTRUSTED;
	return elasticlave_change(eid, (uid_t)uid, (dyn_perm_t)perm);
}

unsigned long sbi_sm_elasticlave_create(uintptr_t pa, __u64 size, unsigned long uid) {
	unsigned long ret;
	/* only an enclave itself can call this SBI */
	if (!cpu_is_enclave_context()) {
		return SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;
	}

	enclave_id eid = cpu_get_enclave_id();

	ret = stop_enclave(encl_regs, SM_REQUEST_ELASTICLAVE_CREATE, eid);
	if (ret == SBI_ERR_SM_ENCLAVE_NOT_RUNNING) // did not successfully switch the context
		goto elasticlave_create_request_clean;

	uintptr_t* request_args = (uintptr_t*)encl_regs[11]; // arg1 would be pointer to the arg array
	setup_enclave_request(eid, REQUEST_ELASTICLAVE_CREATE, request_args, 1, size);

elasticlave_create_request_clean:
	return ret;
}

unsigned long sbi_sm_elasticlave_host_create(uintptr_t pa, uintptr_t size, uintptr_t uid_ret) {
  unsigned long ret;
  if (cpu_is_enclave_context())
    return SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;

  ret = _elasticlave_create(NULL, pa, (void*)uid_ret, size);

  return ret;
}

unsigned long sbi_sm_elasticlave_map(uid_t uid, uintptr_t pa_addr, uintptr_t pa_size) {
	unsigned long ret;
	// both the untrusted code and other enclaves can call this

	enclave_id eid = cpu_is_enclave_context() ? cpu_get_enclave_id() : EID_UNTRUSTED;

	uintptr_t paddr = 0, size = 0;
	ret = elasticlave_map(eid, uid, &paddr, &size);

	ipi_acquire_lock(&encl_lock);
	if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS) {
		if (eid != EID_UNTRUSTED) {
			struct enclave* encl = encl_get(eid);
			assert(!copy_to_enclave(encl, ret_paddr, &paddr, sizeof(paddr)));
			assert(!copy_to_enclave(encl, ret_size, &size, sizeof(size)));
		} else {
			assert(!copy_to_host(ret_paddr, &paddr, sizeof(paddr)));
			assert(!copy_to_host(ret_size, &size, sizeof(size)));
		}
	}
	ipi_release_lock(&encl_lock);

	return ret;
}

unsigned long sbi_sm_elasticlave_unmap(uintptr_t mem_mappings_uid) {
	unsigned long ret;
	enclave_id eid = cpu_is_enclave_context() ? cpu_get_enclave_id() : (enclave_id)EID_UNTRUSTED;
	ret = elasticlave_unmap(eid, uid);
	return ret;
}

unsigned long sbi_sm_elasticlave_destroy(uid_t uid) {
	enclave_id eid = cpu_get_enclave_id();

	uintptr_t paddr = 0;
	unsigned long ret = elasticlave_destroy(eid, uid, &paddr);
	if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
		return ret;

	// notify the OS
  if (eid) {
    ret = stop_enclave(encl_regs, SM_REQUEST_ELASTICLAVE_DESTROY, eid);
    if (ret == SBI_ERR_SM_ENCLAVE_NOT_RUNNING) // did not successfully switch the context
      return ret;

    uintptr_t* request_args = (uintptr_t *)encl_regs[11]; // arg1 would be pointer to the arg array
    setup_enclave_request(eid, REQUEST_ELASTICLAVE_DESTROY, request_args, 1, paddr);
  }
	
	return ret;
}

unsigned long sbi_sm_elasticlave_transfer(uintptr_t uid, uintptr_t eid) {
  return elasticlave_transfer(cpu_get_enclave_id(), uid, eid);
}

unsigned long sbi_sm_elasticlave_share(uintptr_t uid, uintptr_t eid, uintptr_t perm) {
  return elasticlave_share(cpu_get_enclave_id(), uid, eid, st_perm);
}

unsigned long sbi_sm_elasticlave_region_events(uintptr_t event_buf, 
		uintptr_t count_ptr, uintptr_t count_lim) {
	return elasticlave_region_events(cpu_get_enclave_id(), event_buf, 
			count_ptr, (int)count_lim);
}

unsigned long sbi_sm_elasticlave_install_regev(uintptr_t regev_notify){
  if (cpu_is_enclave_context())
    return SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;
  return install_regev_notify(regev_notify) ? ENCLAVE_ILLEGAL_ARGUMENT : ENCLAVE_SUCCESS;
}


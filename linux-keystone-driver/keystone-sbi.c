#include "keystone-sbi.h"

struct sbiret sbi_sm_create_enclave(struct keystone_sbi_create_t* args) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_CREATE_ENCLAVE,
      (unsigned long) args, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_run_enclave(unsigned long eid, unsigned long request_args) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_RUN_ENCLAVE,
      eid, request_args, 0, 0, 0, 0);
}

struct sbiret sbi_sm_destroy_enclave(unsigned long eid, unsigned long enclave_shm_list) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_DESTROY_ENCLAVE,
      eid, (unsigned long) enclave_shm_list, 0, 0, 0, 0);
}

struct sbiret sbi_sm_resume_enclave(unsigned long eid, unsigned long request_args, uintptr_t resp0, uintptr_t resp1) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_RESUME_ENCLAVE,
      eid, request_args, (unsigned long) resp0, (unsigned long) resp1, 0, 0);
}

struct sbiret sbi_sm_print_stats(unsigned long eid, uintptr_t tmp_stats_paddr) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_PRINT_STATS,
      eid, (unsigned long) tmp_stats_paddr, 0, 0, 0, 0);
}

struct sbiret sbi_sm_print_rt_stats(unsigned long eid, uintptr_t tmp_stats_paddr) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_PRINT_RT_STATS,
      eid, (unsigned long) tmp_stats_paddr, 0, 0, 0, 0);
}

struct sbiret sbi_sm_elasticlave_change(__u64 uid, __u64 perm) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_ELASTICLAVE_CHANGE,
      (unsigned long) uid, (unsigned long) perm, 0, 0, 0, 0);
}

struct sbiret sbi_sm_elasticlave_create(uintptr_t pa, __u64 size, unsigned long uid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_ELASTICLAVE_CREATE,
      (unsigned long) pa, (unsigned long) size, uid, 0, 0, 0);
}

struct sbiret sbi_sm_elasticlave_map(uid_t uid, uintptr_t pa_addr, uintptr_t pa_size) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_ELASTICLAVE_MAP,
      (unsigned long) uid, (unsigned long) pa_addr, (unsigned long) pa_size, 0, 0, 0);
}

struct sbiret sbi_sm_elasticlave_unmap(uintptr_t mem_mappings_uid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_ELASTICLAVE_UNMAP,
      (unsigned long) mem_mappings_uid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_elasticlave_destroy(uid_t uid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_ELASTICLAVE_DESTROY,
      (unsigned long) uid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_elasticlave_transfer(uintptr_t uid, uintptr_t eid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_ELASTICLAVE_TRANSFER,
      (unsigned long) uid, (unsigned long) eid, 0, 0, 0, 0);
}

struct sbiret sbi_sm_elasticlave_share(uintptr_t uid, uintptr_t eid, uintptr_t perm) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_ELASTICLAVE_SHARE,
      (unsigned long) uid, (unsigned long) eid, (unsigned long) perm, 0, 0, 0);
}

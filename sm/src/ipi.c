#include <sbi/sbi_fifo.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hsm.h>
#include <sbi/sbi_domain.h>
#include "ipi.h"
#include "pmp.h"
#include "cpu.h"

void sbi_pmp_ipi_local_update(struct sbi_tlb_info *__info)
{
  struct sbi_pmp_ipi_info* info = (struct sbi_pmp_ipi_info *) __info;
  if (info->type == SBI_PMP_IPI_TYPE_SET) {
    pmp_set_keystone(info->rid, (uint8_t) info->perm);
  } else if (info->type == SBI_PMP_IPI_TYPE_UNSET) {
    pmp_unset(info->rid);
  } else {
    update_region_perm(shared_regions + info->rid);
  }
}

void sbi_terminate_ipi_local(struct sbi_tlb_info *__info) {
  struct sbi_terminate_ipi_info* info = (struct sbi_pmp_ipi_info *) __info;
  if (cpu_is_enclave_context()) {
    cpu_set_to_terminate(1);
    try_terminate_enclave(info->regs);
  }
}

void sbi_region_ipi_local(struct sbi_tlb_info *__info) {
  region_ipi_update();
}

void send_and_sync_pmp_ipi(uintptr_t encl_mask, int region_idx, int type, uint8_t perm) // TODO add mask?
{
  ulong mask = 0;
  ulong source_hart = current_hartid();
  struct sbi_tlb_info tlb_info;
  sbi_hsm_hart_started_mask(sbi_domain_thishart_ptr(), 0, &mask);

  SBI_TLB_INFO_INIT(&tlb_info, type, 0, region_idx, perm,
      sbi_pmp_ipi_local_update, source_hart);
  sbi_tlb_request(mask, 0, &tlb_info);
}

void send_and_sync_terminate_ipi(uintptr_t encl_mask, uintptr_t *regs) // TODO add mask?
{
  ulong mask = 0;
  ulong source_hart = current_hartid();
  struct sbi_tlb_info tlb_info;
  sbi_hsm_hart_started_mask(sbi_domain_thishart_ptr(), 0, &mask);

  SBI_TLB_INFO_INIT(&tlb_info, regs, 0, 0, 0,
      sbi_terminate_ipi_local, source_hart);
  sbi_tlb_request(mask, 0, &tlb_info);
}

void send_and_sync_region_ipi(uintptr_t encl_mask) // TODO add mask?
{
  ulong mask = 0;
  ulong source_hart = current_hartid();
  struct sbi_tlb_info tlb_info;
  sbi_hsm_hart_started_mask(sbi_domain_thishart_ptr(), 0, &mask);

  SBI_TLB_INFO_INIT(&tlb_info, 0, 0, 0, 0,
      sbi_region_ipi_local, source_hart);
  sbi_tlb_request(mask, 0, &tlb_info);
}
#ifndef __PMP_IPI_H__
#define __PMP_IPI_H__

#include <sbi/sbi_scratch.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_tlb.h>

#define SBI_PMP_IPI_TYPE_SET    0
#define SBI_PMP_IPI_TYPE_UNSET  1
#define SBI_PMP_IPI_TYPE_SHMEM  2

struct sbi_pmp_ipi_info {
  unsigned long type;
  unsigned long __dummy;
  unsigned long rid;
  unsigned long perm;
};

enum ipi_type {
	IPI_TYPE_PMP,
	IPI_TYPE_REGION,
	IPI_TYPE_TERMINATE
};

void sbi_pmp_ipi_local_update(struct sbi_tlb_info *info);

#define SBI_PMP_IPI_INFO_SIZE sizeof(struct sbi_pmp_ipi_info)

int sbi_pmp_ipi_init(struct sbi_scratch* scratch, bool cold_boot);

int sbi_pmp_ipi_request(ulong hmask, ulong hbase, struct sbi_pmp_ipi_info* info);

void send_and_sync_pmp_ipi(int region_idx, int type, uint8_t perm);

#endif

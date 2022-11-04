#include <sbi/sbi_trap.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_scratch.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_ecall.h>
#include "sm-sbi-opensbi.h"
#include "pmp.h"
#include "sm-sbi.h"
#include "sm.h"
#include "cpu.h"

static int sbi_ecall_keystone_enclave_handler(unsigned long extid, unsigned long funcid,
                     const struct sbi_trap_regs *regs,
                     unsigned long *out_val,
                     struct sbi_trap_info *out_trap)
{
  uintptr_t retval;

  if (funcid <= FID_RANGE_DEPRECATED) { return SBI_ERR_SM_DEPRECATED; }
  else if (funcid <= FID_RANGE_HOST)
  {
    if (cpu_is_enclave_context())
      return SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;
  }
  else if (funcid <= FID_RANGE_ENCLAVE)
  {
    if (!cpu_is_enclave_context())
      return SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED;
  }

  switch (funcid) {
    case SBI_SM_CREATE_ENCLAVE:
      retval = sbi_sm_create_enclave(out_val, regs->a0);
      break;
    case SBI_SM_DESTROY_ENCLAVE:
      retval = sbi_sm_destroy_enclave(regs->a0, regs->a1);
      break;
    case SBI_SM_RUN_ENCLAVE:
      retval = sbi_sm_run_enclave((struct sbi_trap_regs*) regs, regs->a0);
      __builtin_unreachable();
      break;
    case SBI_SM_RESUME_ENCLAVE:
      retval = sbi_sm_resume_enclave((struct sbi_trap_regs*) regs, regs->a0, regs->a2, regs->a3);
      __builtin_unreachable();
      break;
    case SBI_SM_RANDOM:
      *out_val = sbi_sm_random();
      retval = 0;
      break;
    case SBI_SM_ATTEST_ENCLAVE:
      retval = sbi_sm_attest_enclave(regs->a0, regs->a1, regs->a2);
      break;
    // case SBI_SM_GET_SEALING_KEY:
    //   retval = sbi_sm_get_sealing_key(regs->a0, regs->a1, regs->a2);
    //   break;
    case SBI_SM_STOP_ENCLAVE:
      retval = sbi_sm_stop_enclave((struct sbi_trap_regs*) regs, regs->a0);
      __builtin_unreachable();
      break;
    case SBI_SM_EXIT_ENCLAVE:
      retval = sbi_sm_exit_enclave((struct sbi_trap_regs*) regs, regs->a0, regs->a1);
      __builtin_unreachable();
      break;
    case SBI_SM_CALL_PLUGIN:
      retval = sbi_sm_call_plugin(regs->a0, regs->a1, regs->a2, regs->a3);
      break;
  case SBI_SM_ELASTICLAVE_CREATE:
    if(cpu_is_enclave_context())
      retval = sbi_sm_elasticlave_create((struct sbi_trap_regs *)regs, regs->a0);
    else
      retval = sbi_sm_elasticlave_host_create(regs->a0, regs->a1, regs->a2);
    break;
  case SBI_SM_ELASTICLAVE_CHANGE:
    retval = sbi_sm_elasticlave_change(regs->a0, regs->a1);
    break;
	case SBI_SM_ELASTICLAVE_MAP:
	  // arg0: uid
	  // arg1: paddr
	  // arg2: size
	  retval = sbi_sm_elasticlave_map((unsigned int)regs->a0, (uintptr_t *)regs->a1, (uintptr_t *)regs->a2);
	  break;
	case SBI_SM_ELASTICLAVE_UNMAP:
	  retval = sbi_sm_elasticlave_unmap((uintptr_t)regs->a0);
	  break;
	case SBI_SM_ELASTICLAVE_SHARE:
	  retval = sbi_sm_elasticlave_share((uintptr_t)regs->a0, (uintptr_t)regs->a1, (uintptr_t)regs->a2);
	  break;
	case SBI_SM_ELASTICLAVE_TRANSFER:
	  retval = sbi_sm_elasticlave_transfer((uintptr_t)regs->a0, (uintptr_t)regs->a1);
	  break;
	case SBI_SM_ELASTICLAVE_DESTROY:
	  retval = sbi_sm_elasticlave_destroy((struct sbi_trap_regs *)regs, (unsigned int)regs->a0);
	  break;
	case SBI_SM_ELASTICLAVE_REGION_EVENTS:
	  // arg0: buffer for receiving events
	  // arg1: buffer for receiving count
	  // arg2: count limit
    retval = sbi_sm_elasticlave_region_events((uintptr_t)regs->a0, (uintptr_t)regs->a1, (uintptr_t)regs->a2);
      break;
  case SBI_SM_ELASTICLAVE_INSTALL_REGEV:
    retval = sbi_sm_elasticlave_install_regev((uintptr_t)regs->a0);
    break;
	case SBI_SM_PRINT_STATS:
	  retval = sbi_sm_print_stats((unsigned long)regs->a0, (void *)regs->a1);
	  break;
	case SBI_SM_PRINT_RT_STATS:
	  retval = sbi_sm_print_rt_stats((unsigned long)regs->a0, (void *)regs->a1);
    break;
  default:
    retval = SBI_ERR_SM_NOT_IMPLEMENTED;
    break;
  }

  return retval;

}

struct sbi_ecall_extension ecall_keystone_enclave = {
  .extid_start = SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
  .extid_end = SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
  .handle = sbi_ecall_keystone_enclave_handler,
};

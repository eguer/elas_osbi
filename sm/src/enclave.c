//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include "ipi.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>

#define ENCL_MAX  16
#define REGIONS_MAX 8

struct enclave enclaves[ENCL_MAX];
struct region shared_regions[REGIONS_MAX];
#define ENCLAVE_EXISTS(eid) (eid >= 0 && eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];

void try_terminate_enclave(uintptr_t* regs){
    if(cpu_is_enclave_context() && cpu_is_to_terminate()){
        stop_enclave(regs, STOP_TERMINATED, cpu_get_enclave_id());
        cpu_set_to_terminate(0);
    }
}

static void terminate_enclaves(uintptr_t enclave_mask){
    int i, mask;
    for(i = 0, mask = enclave_mask >> 1; mask; ++i, mask >>= 1){
        if(mask & 1){
            enclaves[i].terminated = 1;
        }
    }
    pmp_terminate_global(enclave_mask);
}

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
static inline void context_switch_to_enclave(struct sbi_trap_regs* regs,
                                                struct enclave* encl,
                                                int load_parameters){
  /* save host context */
  swap_prev_state(&encl->threads[0], regs, 1);
  swap_prev_mepc(&encl->threads[0], regs, regs->mepc);
  swap_prev_mstatus(&encl->threads[0], regs, regs->mstatus);

  if(!load_parameters) {
        performance_check_end(&encl->stats.host_execution);
        performance_count(&encl->stats.host_execution);
  }
  performance_check_start(&encl->stats.switch_to_enclave);

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);

  if(load_parameters) {
    // passing parameters for a first run
    csr_write(sepc, (uintptr_t) encl->params.user_entry);
    regs->mepc = (uintptr_t) encl->params.runtime_entry - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    // TODO? add regs->a0 = (uintptr_t) encl->eid;
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) encl->pa_params.dram_base;
    // $a2: (PA) DRAM size,
    regs->a2 = (uintptr_t) encl->pa_params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) encl->pa_params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) eencl->pa_params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) encl->pa_params.free_base;
    // $a6: (VA) utm base,
    regs->a6 = (uintptr_t) encl->params.untrusted_ptr;
    // $a7: (size_t) utm size
    regs->a7 = (uintptr_t) encl->params.untrusted_size;

    // switch to the initial enclave page table
    csr_write(satp, encl->encl_satp);
  }

  switch_vector_enclave();


  ipi_acquire_lock(&encl_lock);
  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;

  for (memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if (shared_regions[memid].type != REGION_INVALID) {
      int old_perm = get_perm(&shared_regions[memid].perm_conf, EID_UNTRUSTED);
      int new_perm = get_perm(&shared_regions[memid].perm_conf, encl->eid);
      if (old_perm != new_perm)
        pmp_set_keystone(shared_regions[memid].pmp_rid, new_perm);
    }
  }

  pmp_set_keystone(encl->epm.pmp_rid, PMP_ALL_PERM);
  int i;
  for (i = 1; i < ENCL_MAX; i++) {
    if (enclaves + i != encl && encl->state != INVALID){
      pmp_set_keystone(encl->utm.pmp_rid, PMP_NO_PERM);
    }
  }
  pmp_set_keystone(encl->utm.pmp_rid, PMP_ALL_PERM);

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(encl));
  cpu_enter_enclave_context(eid);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    struct enclave* encl,
    int return_on_resume){

  performance_check_end(&encl->stats.enclave_execution);
  performance_count(&encl->stats.enclave_execution);

  performance_check_start(&encl->stats.switch_to_host);

  // set PMP
  int memid;
  ipi_acquire_lock(&encl_lock);
  for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if (shared_regions[memid].type != REGION_INVALID){
      int old_perm = get_perm(&shared_regions[memid].perm_conf, encl->eid);
      int new_perm = get_perm(&shared_regions[memid].perm_conf, EID_UNTRUSTED);
      if (old_perm != new_perm){
        pmp_set_keystone(shared_regions[memid].pmp_rid, new_perm);
      }
    }
  }

  pmp_set_keystone(encl->epm.pmp_rid, PMP_NO_PERM);

  int i;
  for (i = 1; i < ENCL_MAX; i++) {
    if (enclaves + i != encl && encl->state != INVALID){
      pmp_set_keystone(encl->utm.pmp_rid, PMP_ALL_PERM);
    }
  }

  osm_pmp_set(PMP_ALL_PERM);

  platform_switch_from_enclave(&(encl));
  cpu_exit_enclave_context();

  ipi_release_lock(&encl_lock);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(&encl->threads[0], regs, return_on_resume);
  swap_prev_mepc(&encl->threads[0], regs, regs->mepc);
  swap_prev_mstatus(&encl->threads[0], regs, regs->mstatus);

  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    csr_clear(mip, MIP_MTIP);
    csr_set(mip, MIP_STIP);
  }
  // if (pending & MIP_MSIP) { // TODO needed?
  //   csr_clear(mip, MIP_MSIP);
  //   csr_set(mip, MIP_SSIP);
  // }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses

  dispatch_events_unlocked(); // TODO needed?

  performance_check_end(&encl->stats.switch_to_host);
  performance_count(&encl->stats.switch_to_host);

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(){
  unsigned int eid;
  int i = 0;

  /* Assumes eids are incrementing values, which they are for now */
  for (eid = 0; eid < ENCL_MAX; eid++) {
    enclaves[i].state = INVALID;

    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[i]));
  }

      // Clear out regions
  for (i = 0; i < REGIONS_MAX; i++) {
    shared_regions[i].type = REGION_INVALID;
    region_perm_config_reset(&shared_regions[i].perm_conf);
  }

  enclaves[0].state = RUNNING;
  enclaves[0].eid = EID_UNTRUSTED;
}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(struct enclave* encl)
{
  static unsigned int eid_max = 0;
  encl->eid = ++eid_max;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
  // TODO clean up?
  // unsigned int eid;

  // spin_lock(&encl_lock);

  // for(eid=0; eid<ENCL_MAX; eid++)
  // {
  //   if(enclaves[eid].state == INVALID){
  //     break;
  //   }
  // }
  // if(eid != ENCL_MAX)
  //   enclaves[eid].state = ALLOCATED;

  // spin_unlock(&encl_lock);

  // if(eid != ENCL_MAX){
  //   *_eid = eid;
  //   return SBI_ERR_SM_ENCLAVE_SUCCESS;
  // }
  // else{
  //   return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  // }
}

static struct enclave* encl_alloc(){
    int i;

    for (i = 0; i < ENCLAVES_MAX; i++) {
        if (enclaves[i].state == INVALID) {
            enclaves[i].state = ALLOCATED;
            return enclaves + i;
        }
    }
    return NULL;
}

static void encl_dealloc(struct enclave* encl){
    encl->state = INVALID;
}

static unsigned long encl_free_eid(struct enclave* encl)
{
  // spin_lock(&encl_lock);
  // enclaves[eid].state = INVALID;
  // spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

// int get_enclave_region_index(unsigned int eid, enum enclave_region_type type){
//   size_t i;
//   for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
//     if(enclaves[eid].regions[i].type == type){
//       return i;
//     }
//   }
//   // No such region for this enclave
//   return -1;
// }

struct enclave* encl_get(unsigned int eid) {
    int i;
    for (i = 0; i < ENCLAVES_MAX; i++)
        if (enclaves[i].eid == eid && enclaves[i].state != INVALID)
            return enclaves + i;
    return NULL;
}

// TODO needed?
int encl_index(struct enclave* encl) {
    return encl ? encl - enclaves : -1;
}

// uintptr_t get_enclave_region_size(unsigned int eid, int memid) {
//   if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
//     return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

//   return 0;
// }

// uintptr_t get_enclave_region_base(unsigned int eid, int memid) {
//   if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
//     return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

//   return 0;
// }

static enclave_ret_code copy_word_to_host(uintptr_t* dest_ptr, uintptr_t value) {
    int region_overlap = 0;
    region_overlap = pmp_detect_region_overlap_atomic((uintptr_t)dest_ptr,
            sizeof(uintptr_t));
    if(!region_overlap)
        *dest_ptr = value;

    if(region_overlap)
        return ENCLAVE_REGION_OVERLAPS;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

enclave_ret_code copy_buffer_to_host(uintptr_t* dest_ptr, uintptr_t* src_ptr, unsigned long size) {
    int region_overlap = 0;
    region_overlap = pmp_detect_region_overlap_atomic((uintptr_t)dest_ptr, size);
    if (!region_overlap)
        memcpy(dest_ptr, src_ptr, size);

    if (region_overlap)
        return ENCLAVE_REGION_OVERLAPS;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
// unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create* dest){

//   int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create));

//   if (region_overlap)
//     return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
//   else
//     return SBI_ERR_SM_ENCLAVE_SUCCESS;
// }

/* copies data from enclave, source must be inside EPM */
// static unsigned long copy_enclave_data(struct enclave* enclave,
//                                           void* dest, uintptr_t source, size_t size) {

//   int illegal = copy_to_sm(dest, source, size);

//   if(illegal)
//     return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
//   else
//     return SBI_ERR_SM_ENCLAVE_SUCCESS;
// }

/* copies data into enclave, destination must be inside EPM */
// static unsigned long copy_enclave_report(struct enclave* enclave,
//                                             uintptr_t dest, struct report* source) {

//   int illegal = copy_from_sm(dest, source, sizeof(struct report));

//   if(illegal)
//     return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
//   else
//     return SBI_ERR_SM_ENCLAVE_SUCCESS;
// }

enclave_ret_code copy_from_host(void* source, void* dest, size_t size) {

    int region_overlap = 0;
    region_overlap = pmp_detect_region_overlap_atomic((uintptr_t) source, size);
    // TODO: Validate that dest is inside the SM.
    if (!region_overlap)
        memcpy(dest, source, size);

    if (region_overlap)
        return ENCLAVE_REGION_OVERLAPS;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

enclave_ret_code copy_to_host(void* dest, void* source, size_t size){

    int region_overlap = 0;
    region_overlap = pmp_detect_region_overlap_atomic((uintptr_t) dest, size);
    if (!region_overlap)
        memcpy(dest, source, size);

    if (region_overlap)
        return ENCLAVE_REGION_OVERLAPS;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int buffer_in_region(struct region* region, void* start, size_t size) {
    uintptr_t region_start = pmp_region_get_addr(region->pmp_rid);
    size_t region_size = pmp_region_get_size(region->pmp_rid);
    if (start >= (void*)region_start
            && start + size <= (void*)(region_start + region_size)) {
        return 1;
    }
    return 0;
}

static int buffer_in_encl_region(struct enclave* enclave,
        void* start, size_t size, int perm){
    if (buffer_in_region(&enclave->epm, start, size) ||
            buffer_in_region(&enclave->utm, start, size))
        return 1;
    unsigned int eid = enclave->eid;
    int i;
    /* Check if the source is in a valid region */
    for (i = 0; i < REGIONS_MAX; i++) {
        if (shared_regions[i].type != REGION_INVALID &&
                (get_perm(&shared_regions[i].perm_conf, eid) & perm) == perm &&
                buffer_in_region(shared_regions + i, start, size))
            return 1;
    }
    return 0;
}

/* copies data from enclave, source must be inside EPM */
static enclave_ret_code copy_from_enclave(struct enclave* enclave,
        void* dest, void* source, size_t size) {
    if (enclave->eid == EID_UNTRUSTED)
        return copy_from_host(dest, source, size);

    int legal = buffer_in_encl_region(enclave, source, size, 1);

    if (legal)
        memcpy(dest, source, size);

    if (!legal)
        return ENCLAVE_ILLEGAL_ARGUMENT;
    else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

size_t copy_string_from_enclave(struct enclave* enclave,
        char* dest, char* source, size_t max_size) {
    if (enclave->eid == EID_UNTRUSTED)
        return 0;
    int i;

    for (i = 0; i < max_size; i ++) {
        if (!buffer_in_encl_region(enclave, source + i, 1, 1)) {
            dest[i] = '\0';
            break;
        }
        dest[i] = source[i];
        if (!dest[i])
            break;
    }
    if (i >= max_size) {
        dest[max_size - 1] = '\0';
        return max_size - 1;
    }
    return i;
}


size_t copy_string_from_host(char* dest, char* source, size_t max_size) {
    int i;

    for (i = 0; i < max_size; i++) {
        if (!pmp_detect_region_overlap_atomic((uintptr_t) (source + i), 1)) {
            dest[i] = '\0';
            break;
        }
        dest[i] = source[i];
        if (!dest[i])
            break;
    }
    if (i >= max_size) {
        dest[max_size - 1] = '\0';
        return max_size - 1;
    }
    return i;
}

/* copies data into enclave, destination must be inside EPM */
enclave_ret_code copy_to_enclave(struct enclave* enclave,
        void* dest, void* source, size_t size) {
    if (enclave->eid == EID_UNTRUSTED)
        return copy_to_host(dest, source, size);
    int legal = buffer_in_encl_region(enclave, dest, size, 1);

    if (legal)
        memcpy(dest, source, size);

    if (!legal){
        return ENCLAVE_ILLEGAL_ARGUMENT;
    } else
        return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create* args) {
  uintptr_t epm_start, epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;

  return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create create_args) {
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;

  unsigned int eid;
  unsigned long ret;
  int region = -1, shared_region = -1;

  /* Runtime parameters */
  if (!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /* set va params */
  struct runtime_va_params_t params = create_args.params;
  struct runtime_pa_params pa_params;
  pa_params.dram_base = base;
  pa_params.dram_size = size;
  pa_params.runtime_base = create_args.runtime_paddr;
  pa_params.user_base = create_args.user_paddr;
  pa_params.free_base = create_args.free_paddr;

  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;

  ipi_acquire_lock(&encl_lock);

  struct enclave *encl = encl_alloc();

  if (encl == NULL)
    goto error;

  if (encl_alloc_eid(encl) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto create_enclave_eid_error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;

  if (pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_ANY, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM, 1, (uintptr_t)-1) ||
            pmp_set_global(shared_region, PMP_ALL_PERM, 1, ENCLAVE_MASK(EID_UNTRUSTED)))
    goto free_shared_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);


  // initialize enclave metadata
    encl->epm.pmp_rid = region;
    encl->epm.type = REGION_EPM;

    encl->utm.pmp_rid = shared_region;
    encl->utm.type = REGION_UTM;

#if __riscv_xlen == 32
  encl->encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  encl->encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif

  encl->n_thread = 0;
  encl->params = params;
  encl->pa_params = pa_params;
  encl->terminated = 0;

  /* Init enclave state (regs etc) */
  clean_state(&encl->threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(encl);
  if (ret)
    goto free_shared_region;

  /* Validate memory, prepare hash and signature for attestation */
  // ipi_acquire_lock(&encl_lock); // FIXME This should error for second enter.
  ret = validate_and_hash_enclave(encl);
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto free_platform;

  encl->state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = encl->eid;

  /* Initialise the performance stats */
  performance_stats_init(&encl->stats.switch_to_enclave);
  performance_stats_init(&encl->stats.switch_to_host);
  performance_stats_init(&encl->stats.enclave_execution);
  performance_stats_init(&encl->stats.host_execution);

  ipi_release_lock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

free_platform: 
    ipi_release_lock(&encl_lock); // TODO need to unlock in other places?
    platform_destroy_enclave(encl);
free_shared_region:
    pmp_region_free_atomic(shared_region);
free_region:
    pmp_region_free_atomic(region);
free_encl_idx:
    encl_free_eid(encl);
create_enclave_eid_error:
    encl_dealloc(encl);
error:
    return ret;
}

static uintptr_t remove_region(struct region* region, int dry) {
    uintptr_t affected_enclaves = 0;
    int i;
    void* base;
    size_t size;
    region_id rid;

    if (!dry) {
        region->type = REGION_INVALID;
        rid = region->pmp_rid;
        base = (void*) pmp_region_get_addr(rid);
        size = (size_t) pmp_region_get_size(rid);
        memset((void*) base, 0, size); // reset contents to 0 to prevent leaking secrets to OS
    }

    for (i = 0; i < ENCLAVES_MAX; i++) {
        if(enclaves[i].state != INVALID){
            struct perm_config* pconf = get_perm_conf_by_eid(&region->perm_conf, enclaves[i].eid);
            if (pconf && pconf->maps > 0) {
                affected_enclaves |= ENCLAVE_MASK(i);
            }
        }
    }

    if (!dry) {
        region_perm_config_reset(&region->perm_conf);
        pmp_unset_global(rid);
        pmp_region_free_atomic(rid);
    }

    return affected_enclaves;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(unsigned int eid, struct enclave_shm_list* shm_list) {
  int destroyable;

  memset(shm_list, 0, sizeof(struct enclave_shm_list));

  ipi_acquire_lock(&encl_lock);

  struct enclave *encl = encl_get(eid);

  destroyable = (ENCLAVE_EXISTS(encl)
                 && encl->state <= STOPPED);

  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if (destroyable)
    encl->state = DESTROYING;

  if(!destroyable)
    goto destory_failure;

  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(encl);

  // 1. clear all the data in the enclave pages
  int i, j;
  unsigned int shm_count = 0;

  for (i = 0; i < REGIONS_MAX; i++) {
    if (shared_regions[i].type == REGION_INVALID &&
            shared_regions[i].perm_conf.owner_id == eid) {
      //my shared region
      shm_list->shms[shm_count].pa = (uintptr_t)shared_regions[i].paddr;
      shm_list->shms[shm_count].size = (uintptr_t)shared_regions[i].size;
      ++ shm_count;
      uintptr_t reg_affected_mask = remove_region(shared_regions + i, 1);
      region_events_add(reg_affected_mask & ~ENCLAVE_MASK(encl_idx),
          shared_regions[i].uid, REGION_EVENT_DESTROYED, 0);
      affected_mask |= reg_affected_mask;
    }
  }

  for(i = 0; i < REGIONS_MAX; i ++) {
    if (shared_regions[i].type != REGION_INVALID && 
            shared_regions[i].perm_conf.owner_id == eid){
      // my shared region
      remove_region(shared_regions + i, 0);
    }
  }
  send_encl_ipis(affected_mask & ~ENCLAVE_MASK(encl_idx), IPI_TYPE_REGION,
          NULL, 1);

  // 2. free pmp region for UTM
  pmp_unset_global(encl->epm.pmp_rid);
  pmp_region_free_atomic(encl->epm.pmp_rid);
  pmp_unset_global(encl->utm.pmp_rid);
  pmp_region_free_atomic(encl->utm.pmp_rid);

  encl->encl_satp = 0;
  encl->n_thread = 0;
  encl->params = (struct runtime_va_params_t) {0};
  encl->pa_params = (struct runtime_pa_params) {0};
  encl->region_event_n = 0;

  // 3. release eid
  encl_free_eid(encl);
  encl_dealloc(encl);

  ipi_release_lock(&encl_lock);

  shm_list->shm_count = shm_count;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;

destory_failure:
    ipi_release_lock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;
}


unsigned long run_enclave(struct sbi_trap_regs *regs, unsigned int eid)
{
  int runable;

  ipi_acquire_lock(&encl_lock);

  struct enclave* encl = encl_get(eid);

  runable = (ENCLAVE_EXISTS(eid) && encl->state == FRESH);

  if (runable) {
    encl->state = RUNNING;
    encl->n_thread++;
  }

  ipi_release_lock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  context_switch_to_enclave(regs, eid, 1);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, unsigned int eid) {
  int exitable;

  ipi_acquire_lock(&encl_lock);

  struct enclave* encl = encl_get(eid);

  exitable = eid != EID_UNTRUSTED && encl->state == RUNNING;

  if (exitable) {
    encl->n_thread--;
    if (encl->n_thread == 0)
      encl->state = STOPPED;
  }

  if(rt_stats_ptr)
    copy_from_enclave(encl, &encl->rt_stats, 
        (void*)rt_stats_ptr, sizeof(struct enclave_rt_stats)); // copy the stats in runtime
  
  ipi_release_lock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, unsigned int eid) {
  int stoppable;

  ipi_acquire_lock(&encl_lock);

  struct enclave* encl = encl_get(eid);

  stoppable = eid != EID_UNTRUSTED && encl->state == RUNNING;
  if (stoppable) {
    encl->n_thread--;
    if(encl->n_thread == 0)
      encl->state = STOPPED;
  }

  ipi_release_lock(&encl_lock);

  if (!stoppable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, encl, 
            request == STOP_EDGE_CALL_HOST ||
            request == SM_REQUEST_ELASTICLAVE_CREATE || 
            request == SM_REQUEST_ELASTICLAVE_DESTROY ||
            request == STOP_YIELD);
  
  performance_check_start(&encl->stats.host_execution);

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_YIELD):
      return SBI_ERR_SM_ENCLAVE_YIELDED;
    case(STOP_CALL_RETURN):
      return SBI_ERR_SM_ENCLAVE_CALL_RETURN;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    case(SM_REQUEST_ELASTICLAVE_CREATE):
      return SBI_ERR_SM_REQUEST_ELASTICLAVE_CREATE;
    case(SM_REQUEST_ELASTICLAVE_DESTROY):
      return SBI_ERR_SM_REQUEST_ELASTICLAVE_DESTROY;
    case(STOP_TERMINATED):
      return SBI_ERR_SM_ENCLAVE_TERMINATED;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

static unsigned long process_request_response(uintptr_t* host_regs, struct enclave* encl, 
        uintptr_t resp0, uintptr_t resp1, uintptr_t* scratch) {
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long _elasticlave_create(struct enclave* encl, uintptr_t paddr,
        void* uid_ret, \
        uintptr_t size) {
    unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    int region;
    ret = pmp_region_init_atomic(paddr, size, PMP_PRI_ANY, &region, 0);

    if (ret)
        goto elasticlave_create_clean;

    ipi_acquire_lock(&encl_lock);

    int region_id = get_region_index(shared_regions, REGION_INVALID);
    if (region_id == -1) {
        ret = SBI_ERR_SM_ENCLAVE_REGION_MAX_REACHED;
        goto elasticlave_create_pmp_clean;
    }

    shared_regions[region_id].pmp_rid = region;
    shared_regions[region_id].uid = (uid_t)region_id + 1; 

    if (encl == NULL)
        ret = copy_to_host(uid_ret, &shared_regions[region_id].uid, sizeof(uid_t));
    else
        ret = copy_to_enclave(encl, uid_ret, \
                &shared_regions[region_id].uid, sizeof(uid_t)); // return the uid

    if (ret != SBI_ERR_SM_ENCLAVE_SUCCESS)
        goto elasticlave_create_region_clean;

    shared_regions[region_id].paddr = paddr;
    shared_regions[region_id].size = size;
    shared_regions[region_id].type = REGION_SHARED;
    // set up the owner
    shared_regions[region_id].perm_conf.owner_id = encl_eid(encl);

    struct perm_config* perm_conf = get_new_perm_config(&shared_regions[region_id].perm_conf);
    if (perm_conf == NULL)
        goto elasticlave_create_pmp_clean;
    perm_conf->eid = encl_eid(encl);
    perm_conf->st_perm = PERM_FULL; // owner automatically gets full static permissions
    perm_conf->dyn_perm = PERM_NULL;

    if (pmp_shmem_update_global(region_id, (uintptr_t)-1)) {
        ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
        goto elasticlave_create_pmp_clean;
    }

    ipi_release_lock(&encl_lock);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;

elasticlave_create_region_clean:
    shared_regions[region_id].type = REGION_INVALID;
elasticlave_create_pmp_clean:
    ipi_release_lock(&encl_lock);
    pmp_region_free_atomic(region);
elasticlave_create_clean:
    return ret;
}

static unsigned long finish_request_response(uintptr_t* host_regs, struct enclave* encl, uintptr_t resp0, uintptr_t resp1, uintptr_t scratch) {
    unsigned long ret = SBI_ERR_SM_ENCLAVE_SUCCESS;
    switch(encl->request.type) {
      case REQUEST_ELASTICLAVE_CREATE:
        // resp0: paddr
        // host_regs[10]: size
        // host_regs[11]: uid_ret
        ret = _elasticlave_create(encl, resp0, (void*)host_regs[11], \
                host_regs[10]);
        break;
      case REQUEST_ELASTICLAVE_DESTROY:
        break; // no need to do anything
      default:;
    }

    if (ret == SBI_ERR_SM_ENCLAVE_SUCCESS) {
        encl->request.type = REQUEST_NO_REQUEST;
    } 

    return ret;
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, unsigned int eid) {
  int resumable;

  ipi_acquire_lock(&encl_lock);

  struct enclave* encl = encl_get(eid);

  resumable = (ENCLAVE_EXISTS(encl)
                && (encl->state == RUNNING || encl->state == STOPPED)
                && encl->n_thread < MAX_ENCL_THREADS) && !encl->terminated;

  if (!resumable) {
    ipi_release_lock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    encl->n_thread++;
    encl->state = RUNNING;
  }
  ipi_release_lock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  context_switch_to_enclave(regs, eid, 0);

  // TODO decide what to do here? (in original depends on ret val of context_switch_to_enclave
  // but that always returns success..? so never called..?)
  // finish_request_response(host_regs, encl, arg1, arg2, request_response_scratch);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, unsigned int eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  ipi_acquire_lock(&encl_lock);

  struct enclave* encl = encl_get(eid);

  attestable = (ENCLAVE_EXISTS(encl)
                && (encl->state >= FRESH));

  if (!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_from_enclave(encl, report.enclave.data, (void*)data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report.enclave.hash, encl->hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  /* copy report to the enclave */
  ret = copy_to_enclave(encl,
        (void*)report_ptr,
        &report,
        sizeof(struct report));

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  ipi_release_lock(&encl_lock);
  return ret;
}

// lend the region to another enclave
static unsigned long elasticlave_change_unlocked(unsigned int eid, uid_t uid, dyn_perm_t dyn_perm) {
  struct enclave* encl = encl_get(eid);

  if (!ENCLAVE_EXISTS(encl))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  struct region* reg = get_region_by_uid(shared_regions, REGIONS_MAX, uid);

  if (reg == NULL) 
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT; // region does not exist

  int change_res = change_dyn_perm(&reg->perm_conf, eid, dyn_perm);
  uintptr_t accessors_mask;
  int encl_idx;

  switch(change_res) {
    case 1: 
      update_region_perm(reg);
      break;
    case 2:
      accessors_mask = get_accessors_mask(&reg->perm_conf);
      encl_idx = encl_index(encl);
      if (dyn_perm & PERM_L) {
        // lock acquired, notify first before updating pmp
        region_events_add(accessors_mask & ~ENCLAVE_MASK(encl_idx), uid,
                      REGION_EVENT_ACQUIRED, 1);
        pmp_shmem_update_global(reg - shared_regions, accessors_mask);
      } else{
        // lock released, update pmp first before notifying
        pmp_shmem_update_global(reg - shared_regions, accessors_mask);
        region_events_add(accessors_mask & ~ENCLAVE_MASK(encl_idx), uid,
                      REGION_EVENT_RELEASED, 1);
      }
      break;
    default:
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT; // change in permission not allowed
  }

  return SBI_ERR_SM_ENCLAVE_SUCCESS;

elasticlave_change_fail:
  return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
}

unsigned long elasticlave_change(unsigned int eid, uid_t uid, dyn_perm_t dyn_perm) {
  ipi_acquire_lock(&encl_lock);
  enclave_ret_code ret = elasticlave_change_unlocked(eid, uid, dyn_perm);
  ipi_release_lock(&encl_lock);
  return ret;
}

unsigned long elasticlave_map(unsigned int eid, uid_t uid,
        uintptr_t* ret_paddr, uintptr_t* ret_size){
  int i;
  ipi_acquire_lock(&encl_lock);

  struct enclave* encl = encl_get(eid);
  for(i = 0; i < REGIONS_MAX; i ++) {
    if (shared_regions[i].type != REGION_SHARED)
        continue;

    if (shared_regions[i].uid != uid){
        continue;
    }

    struct perm_config* pconf = get_perm_conf_by_eid(&shared_regions[i].perm_conf, eid);

    if (pconf == NULL)
        goto elasticlave_map_fail;

    inc_maps(pconf);
    *ret_paddr = shared_regions[i].paddr;
    *ret_size = shared_regions[i].size;

    ipi_release_lock(&encl_lock);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
elasticlave_map_fail:
    ipi_release_lock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
}

enclave_ret_code elasticlave_unmap(unsigned int eid, uid_t uid){
  int i;

  ipi_acquire_lock(&encl_lock);

  struct enclave* encl = encl_get(eid);

  if (eid != EID_UNTRUSTED && !ENCLAVE_EXISTS(encl))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  for(i = 0; i < REGIONS_MAX; i ++) {
    if (shared_regions[i].type != REGION_SHARED)
      continue;

    if (shared_regions[i].uid != uid)
      continue;
    
    struct perm_config* pconf = get_perm_conf_by_eid(&shared_regions[i].perm_conf, eid);
        
    if(pconf == NULL || dec_maps(pconf) <= 0)
      goto elasticlave_unmap_fail;
    
    ipi_release_lock(&encl_lock);

    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
elasticlave_unmap_fail:
  ipi_release_lock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
}

unsigned long elasticlave_share(
        unsigned int eid, // issuing enclave, not passed to sm as arg
        uid_t uid,
        unsigned int oeid,
        st_perm_t st_perm) {

  if (st_perm == PERM_NULL) // doesn't allow sharing with null permissions
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  struct enclave* encl = encl_get(eid);
  struct enclave* oencl = encl_get(oeid);

  if (oeid != EID_UNTRUSTED && !ENCLAVE_EXISTS(oencl))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  struct region* region = get_region_by_uid(shared_regions, REGIONS_MAX, uid);

  if (region == NULL || !share_allowed(&region->perm_conf, eid) ||
          get_st_perm(&region->perm_conf, oeid) != PERM_NULL) // can't share twice
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  struct perm_config* p_conf = get_new_perm_config(&region->perm_conf);

  if (!p_conf)
      return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;

  p_conf->eid = oeid;
  p_conf->st_perm = st_perm;
  p_conf->dyn_perm = PERM_NULL;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long elasticlave_transfer(
        unsigned int eid,
        uid_t uid,
        unsigned int oeid) {

  if (eid == oeid)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  struct region* region = get_region_by_uid(shared_regions, REGIONS_MAX, uid);
  struct enclave* encl = encl_get(eid);
  struct enclave* oencl = encl_get(oeid);

  if (oeid != EID_UNTRUSTED && !ENCLAVE_EXISTS(oencl))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (region == NULL)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  if (region->perm_conf.lock_holder != eid)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT; // eid is not the current lock holder

  struct perm_config* perm_conf_other = get_perm_conf_by_eid(&region->perm_conf, oeid);

  if (perm_conf_other == NULL || !(perm_conf_other->st_perm & PERM_L))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT; // oeid not allowed to hold lock

  struct perm_config* perm_conf_own = get_perm_conf_by_eid(&region->perm_conf, eid);
  assert(perm_conf_own->dyn_perm & PERM_L);

  perm_conf_other->dyn_perm |= PERM_L;
  perm_conf_own->dyn_perm &= ~PERM_L;

  region_events_add(ENCLAVE_MASK(encl_index(oencl)), 
            uid, REGION_EVENT_TRANSFERRED, 1); 

  region->perm_conf.lock_holder = oeid;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

enclave_ret_code elasticlave_destroy(unsigned int eid, uid_t uid, uintptr_t* paddr) {
  struct enclave* encl = encl_get(eid);
  struct region* region = get_region_by_uid(shared_regions, REGIONS_MAX, uid);

  if (region == NULL || region->perm_conf.owner_id != eid)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  *paddr = region->paddr;
  uintptr_t affected_enclaves = remove_region(region, 1);
  affected_enclaves &= ~ENCLAVE_MASK(encl_index(encl));
  region_events_add(affected_enclaves, uid, REGION_EVENT_DESTROYED, 1);
  remove_region(region, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}


unsigned long elasticlave_region_events(unsigned int eid, uintptr_t event_buf, 
        uintptr_t count_ptr, 
        int count_lim) {
  struct enclave* encl = encl_get(eid);

  if (eid != EID_UNTRUSTED && !ENCLAVE_EXISTS(encl))
      return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  uintptr_t region_event_n = (uintptr_t)encl->region_event_n; 
  uintptr_t d[2];
  uintptr_t i;

  for (i = 0; i < region_event_n && i < count_lim; i++, event_buf += sizeof(d)) {
      d[0] = (uintptr_t)encl->region_events[i].uid;
      d[1] = (uintptr_t)encl->region_events[i].type;

      if (copy_to_enclave(encl, (void*)event_buf, d, sizeof(d)))
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  }

  if (copy_to_enclave(encl, (void*)count_ptr, &i, sizeof(uintptr_t)))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  region_events_pop(encl, (int)i); // pop those already returned
  dispatch_events_unlocked();

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

void setup_enclave_request(unsigned int eid, enum enclave_request_type request_type, 
        uintptr_t* host_args, int num, ...) {
  ipi_acquire_lock(&encl_lock);

  struct enclave* encl = encl_get(eid);
  encl->request.type = request_type;

  va_list arglist;
  va_start(arglist, num);

  int i;
  for (i = 0; i < num; i++){
    encl->request.args[i] = va_arg(arglist, uintptr_t);
  }

  va_end(arglist);

  if (host_args)
    copy_buffer_to_host(host_args, encl->request.args, 
          sizeof(encl->request.args));

  ipi_release_lock(&encl_lock);
}

void region_events_add(uintptr_t enclave_mask, uid_t uid,
        enum region_event_type type, int send_ipi) {
    int i, encl_idx, event_n;
    struct enclave* enclave;

    for (encl_idx = 0; encl_idx < ENCLAVES_MAX; encl_idx++) {
      if (enclave_mask & ENCLAVE_MASK(encl_idx)) {
        enclave = enclaves + encl_idx;
        event_n = enclave->region_event_n;
        for(i = 0; i < event_n && enclave->region_events[i].uid != uid; i ++);
        assert(i < REGIONS_MAX);
        enclave->region_events[i].uid = uid;
        enclave->region_events[i].type = type;
        if(i == event_n)
          ++ enclave->region_event_n;
      }
    }

    if (send_ipi)
        send_encl_ipis(enclave_mask, IPI_TYPE_REGION, NULL, 1);
}

void region_events_pop(struct enclave* enclave, int count) {
  if (count > enclave->region_event_n) {
    enclave->region_event_n = 0;
    return;
  }

  enclave->region_event_n -= count;
  int i;
  for(i = 0; i < enclave->region_event_n; i ++)
    enclave->region_events[i] = enclave->region_events[i + count];
}

void dispatch_events_unlocked(){
  struct enclave* enclave = encl_get(cpu_get_enclave_id());

  if (enclave->region_event_n == 0) {
    clear_csr(mip, MIP_SSIP);
  } else {
    set_csr(mip, MIP_SSIP);
  }
}

void region_ipi_update(int* args) {
  dispatch_events_unlocked();
}

// for notifying the host application
static uintptr_t regev_notify;

int install_regev_notify(uintptr_t ptr) {
  if (regev_notify || !ptr)
    return -1;
  regev_notify = ptr;
  return 0;
}

// unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
//                                  size_t key_ident_size, unsigned int eid)
// {
//   struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
//   int ret;

//   /* derive key */
//   ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
//                               (const unsigned char *)key_ident, key_ident_size,
//                               (const unsigned char *)enclaves[eid].hash);
//   if (ret)
//     return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

//   /* sign derived key */
//   sm_sign((void *)key_struct->signature, (void *)key_struct->key,
//           SEALING_KEY_SIZE);

//   return SBI_ERR_SM_ENCLAVE_SUCCESS;
// }

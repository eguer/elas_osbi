//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif

#include "sm.h"
#include "pmp.h"
#include "thread.h"
#include "crypto.h"

// Special target platform header, set by configure script
#include TARGET_PLATFORM_HEADER

#define ATTEST_DATA_MAXLEN  1024
/* TODO: does not support multithreaded enclave yet */
#define MAX_ENCL_THREADS 1
#define ENCLAVE_MASK(x) ((uintptr_t)1 << ((x) + 1))

typedef enum {
  INVALID = -1,
  DESTROYING = 0,
  ALLOCATED,
  FRESH,
  STOPPED,
  RUNNING,
} enclave_state;

/* Enclave stop reasons requested */
#define STOP_TIMER_INTERRUPT  0
#define STOP_EDGE_CALL_HOST   1
#define STOP_EXIT_ENCLAVE     2
#define STOP_YIELD			      3
#define STOP_CALL_RETURN   	  4
#define STOP_TERMINATED		    5

#define EID_UNTRUSTED	0

/* For now, eid's are a simple unsigned int */
extern struct region shared_regions[];

struct enclave_stats {
  /* performance measurements */
  struct performance_stats switch_to_enclave;
  struct performance_stats switch_to_host;
  struct performance_stats enclave_execution;
  struct performance_stats host_execution;
};

enum region_event_type {
	//REGION_EVENT_INVALID = 0,
	REGION_EVENT_TRANSFERRED = 0,
	REGION_EVENT_ACQUIRED = 1,
	REGION_EVENT_RELEASED = 2,
	REGION_EVENT_DESTROYED = 3
};

struct region_event {
	uid_t uid;
	enum region_event_type type;
};

struct enclave_rt_stats {
	struct performance_stats args_copy_stats;
	struct performance_stats retval_copy_stats;
	struct performance_stats page_fault_stats;
	struct performance_stats stats_sbi;
	struct performance_stats stats_rt;
	struct performance_stats stats_boot_sbi;
	struct performance_stats stats_boot;
};

/* Metadata around memory regions associate with this enclave
 * EPM is the 'home' for the enclave, contains runtime code/etc
 * UTM is the untrusted shared pages
 * OTHER is managed by some other component (e.g. platform_)
 * INVALID is an unused index
 */
/* enclave metadata */
struct enclave
{
  //spinlock_t lock; //local enclave lock. we don't need this until we have multithreaded enclave
  enclave_id eid; //enclave id
  unsigned long encl_satp; // enclave's page table base
  enclave_state state; // global state of the enclave
  int terminated;

  /* Physical memory regions associate with this enclave */
  struct region epm, utm;

  /* measurement */
  byte hash[MDSIZE];
  byte sign[SIGNATURE_SIZE];

  /* parameters */
  struct runtime_va_params_t params;
  struct runtime_pa_params pa_params;

  /* enclave execution context */
  unsigned int n_thread;
  struct thread_state threads[MAX_ENCL_THREADS];

  struct platform_enclave_data ped;
  struct enclave_request request;

  struct enclave_stats stats;
  struct enclave_rt_stats rt_stats;

  // pending notifications regarding memory regions
  struct region_event region_events[REGIONS_MAX];
  int region_event_n; 
};

/* attestation reports */
struct enclave_report
{
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};

struct sm_report
{
  byte hash[MDSIZE];
  byte public_key[PUBLIC_KEY_SIZE];
  byte signature[SIGNATURE_SIZE];
};

struct report
{
  struct enclave_report enclave;
  struct sm_report sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

struct enclave_shm {
	uintptr_t pa;
	uintptr_t size;
};

struct enclave_shm_list {
	unsigned int shm_count;
	struct enclave_shm shms[16];
};

/* sealing key structure */ // todo add back in?
// #define SEALING_KEY_SIZE 128
// struct sealing_key
// {
//   uint8_t key[SEALING_KEY_SIZE];
//   uint8_t signature[SIGNATURE_SIZE];
// };

/*** SBI functions & external functions ***/
// callables from the host
unsigned long create_enclave(unsigned long *eid, struct keystone_sbi_create create_args);
unsigned long destroy_enclave(enclave_id eid, struct enclave_shm_list* shm_list);
unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid);
unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid, uintptr_t resp0, uintptr_t resp1);
// callables from the enclave
unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid, uintptr_t rt_stats_ptr);
unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid);
unsigned long attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size, enclave_id eid);
unsigned long elasticlave_change(enclave_id eid, uid_t uid, dyn_perm_t dyn_perm);
unsigned long elasticlave_map(enclave_id eid, uid_t uid, uintptr_t* ret_paddr, uintptr_t* ret_size);
unsigned long elasticlave_unmap(enclave_id eid, uid_t uid);
unsigned long elasticlave_destroy(enclave_id eid, uid_t uid, uintptr_t* paddr);
unsigned long elasticlave_region_events(enclave_id eid, uintptr_t event_buf, uintptr_t count_ptr, int count_lim);

/* attestation and virtual mapping validation */
unsigned long validate_and_hash_enclave(struct enclave* enclave);
// TODO: These functions are supposed to be internal functions.
void enclave_init_metadata();
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create* dest, size_t size);
// int get_enclave_region_index(enclave_id eid, enum enclave_region_type type); todo don't need?
// uintptr_t get_enclave_region_base(enclave_id eid, int memid);
// uintptr_t get_enclave_region_size(enclave_id eid, int memid);
// unsigned long get_sealing_key(uintptr_t seal_key, uintptr_t key_ident, size_t key_ident_size, enclave_id eid);

unsigned long copy_to_enclave(struct enclave* enclave, void* dest, void* source, size_t size);
unsigned long copy_to_host(void* dest, void* source, size_t size);
void setup_enclave_request(enclave_id eid, enum enclave_request_type request_type, uintptr_t* host_args, int num, ...);
unsigned long copy_buffer_to_host(uintptr_t* dest_ptr, uintptr_t* src_ptr, unsigned long size);
size_t copy_string_from_enclave(struct enclave* enclave, char* dest, char* source, size_t max_size);
size_t copy_string_from_host(char* dest, char* source, size_t max_size);
void try_terminate_enclave(uintptr_t* regs);

unsigned long elasticlave_share(enclave_id eid, uid_t uid, enclave_id oeid, st_perm_t st_perm);

unsigned long elasticlave_transfer(enclave_id eid, uid_t uid, enclave_id oeid);

struct enclave* encl_get(enclave_id eid);

int encl_index(struct enclave* encl);

// region events
void region_events_add(uintptr_t enclave_mask, uid_t uid, enum region_event_type type, int send_ipi);
void region_ipi_update(int* args);
void dispatch_events_unlocked();
void region_events_pop(struct enclave* enclave, int count);

unsigned long _elasticlave_create(struct enclave* encl, uintptr_t paddr, void* uid_ret, uintptr_t size);

static inline enclave_id encl_eid(struct enclave* encl) {
  if(encl == NULL)
    return EID_UNTRUSTED;
  return encl->eid;
}

int install_regev_notify(uintptr_t ptr);
#endif

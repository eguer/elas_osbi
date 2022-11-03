//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include "./common.h"
extern "C" {
#include "common/sha3.h"
}
#include "ElfFile.hpp"
#include "Error.hpp"
#include "KeystoneDevice.hpp"
#include "Memory.hpp"
#include "Params.hpp"
#include "edge_dispatch.hpp"

#define MAX_DR_REQUEST_ARGS 8

namespace Keystone {

class Enclave;
typedef void (*NewMemHandler)(void*);
typedef sha3_ctx_t hash_ctx_t;

#define REGIONS_MAX 32

inline static void print_enclave_stats(struct enclave_stats* stats){
	performance_stats_print_total(&stats->switch_to_enclave, "Switch to enclave");
	performance_stats_print_total(&stats->switch_to_host, "Switch to host");
	performance_stats_print_total(&stats->enclave_execution, "Enclave execution");
	performance_stats_print_total(&stats->host_execution, "Host execution");
}

inline static void print_enclave_rt_stats(struct enclave_rt_stats* rt_stats){
	performance_stats_print(&rt_stats->args_copy_stats, "RT Args Copy");
	performance_stats_print_total(&rt_stats->args_copy_stats, "RT Args Copy");
	performance_stats_print(&rt_stats->retval_copy_stats, "RT Retval Copy");
	performance_stats_print_total(&rt_stats->retval_copy_stats, "RT Retval Copy");
	performance_stats_print_total(&rt_stats->page_fault_stats, "RT Page Fault");
	performance_stats_print_total(&rt_stats->stats_sbi, "RT SBI");
	performance_stats_print_total(&rt_stats->stats_rt, "RT Total");
	performance_stats_print_total(&rt_stats->stats_boot_sbi, "RT Boot SBI");
	performance_stats_print_total(&rt_stats->stats_boot, "RT Boot Total");
}

enum enclave_state {
	ENCLAVE_STATE_INVALID,
	ENCLAVE_STATE_INITIALISED,
	ENCLAVE_STATE_LAUNCHED,
	ENCLAVE_STATE_BLOCKED,
	ENCLAVE_STATE_ENDED
};

struct ecall_stats {
	struct performance_stats args_copy_stats;
	struct performance_stats retval_copy_stats; 
};

inline static void init_ecall_stats(struct ecall_stats* stats){
	performance_stats_init(&stats->args_copy_stats);
	performance_stats_init(&stats->retval_copy_stats);
}

inline static void print_ecall_stats(struct ecall_stats* stats){
	performance_stats_print(&stats->args_copy_stats, "Host args copy (SDK)");
	performance_stats_print_total(&stats->args_copy_stats, "Host args copy (SDK) Total");
	performance_stats_print(&stats->retval_copy_stats, "Host retval copy (SDK)");
	performance_stats_print_total(&stats->retval_copy_stats, "Host retval copy (SDK) Total");
}

class EdgeCallDispatcher;

class Enclave {
  private:
    enum enclave_state state;
    Params params;
    ElfFile* runtimeFile;
    ElfFile* enclaveFile;
    Memory* pMemory;
    KeystoneDevice* pDevice;
    char hash[MDSIZE];
    hash_ctx_t hash_ctx;
    uintptr_t runtime_stk_sz;
    uintptr_t pt_free_list; // todo needed?
    uintptr_t epm_free_list;
    uintptr_t utm_free_list;
    int eid; // TODO remove
    int fd; // TODO remove
    void* shared_buffer;
    size_t shared_buffer_size;
    void* o_shared_buffer;
    size_t o_shared_buffer_size;
    struct ecall_stats ecall_stats;
    struct performance_stats run_stats;
    unsigned long target_call_id; /* ecall */
    EdgeCallDispatcher* ocall_dispatcher;
    bool mapUntrusted(size_t size);
    bool allocPage(uintptr_t va, uintptr_t src, unsigned int mode);
    bool initStack(uintptr_t start, size_t size, bool is_rt);
    Error loadUntrusted();
    bool mapElf(ElfFile* file);
    Error loadElf(ElfFile* file);
    Error validate_and_hash_enclave(struct runtime_params_t args);
    NewMemHandler new_mem_handler;

    bool initFiles(const char*, const char*);
    bool initDevice();
    bool prepareEnclave(uintptr_t alternatePhysAddr);
    bool initMemory();
    void process_new_memory_region(uintptr_t size);

    struct keystone_ioctl_run_enclave run_args;
    uintptr_t dr_request_args[MAX_DR_REQUEST_ARGS];

    // directly return after being stopped
    uid_t region_uids[REGIONS_MAX];
    void* region_bufs[REGIONS_MAX];
    int region_n;

  public:
    void* custom; // custom data

    Enclave();
    ~Enclave();
    void* getSharedBuffer();
    size_t getSharedBufferSize();
    int getSID() const;
    Error registerOcallDispatch(EdgeCallDispatcher* dispatcher);
    Error init(const char* filepath, const char* runtime, Params parameters);
    Error init(const char *eapppath, const char *runtimepath, Params _params, uintptr_t alternate_phys_addr);
    Error measure(const char* filepath, const char* runtime, Params parameters);
    Error destroy();
    Error runOnce(int* ret_code);
    Error run(uintptr_t* ret = nullptr);
    Error call(unsigned long call_id, void* data, size_t data_len, void* return_buffer, size_t return_len);
    Error call_with_stats(unsigned long call_id, void* data, size_t data_len, void* return_buffer, size_t return_len, struct ecall_stats* stats);
    int print_sm_stats(struct enclave_stats* stats);
    int print_rt_stats(struct enclave_rt_stats* rt_stats);
    void add_region_buffer(uid_t uid, void* buf);
    void* get_region_buffer(uid_t uid) const;

    void set_target_call(unsigned long target);
    void print_call_stats();
    Error registerNewMemHandler(NewMemHandler handler);
    struct performance_stats get_run_stats() const;
    enum enclave_state getState() const;
    friend class EnclaveGroup;

    // elasticlave interfaces
    Error elasticlave_share(uid_t uid, unsigned long perm);
    Error elasticlave_transfer(uid_t uid);

    bool futex_initialised;
    int *shared_futex_start, *local_futex_start;
    uintptr_t in_enclave_shared_futex_start; // the address inside enclave
    pthread_mutex_t* futex_mutex;
};

#define ENCLAVE_GROUP_MAX 8

class EnclaveGroup {
	private:
		Enclave* enclaves[ENCLAVE_GROUP_MAX];
		int enclave_n;
	public:
		EnclaveGroup() : enclave_n(0) {}
		void addEnclave(Enclave* enclave){
			enclaves[enclave_n ++] = enclave;
		}
		Error run();
};

uint64_t
calculate_required_pages(
    uint64_t eapp_sz, uint64_t eapp_stack_sz, uint64_t rt_sz,
    uint64_t rt_stack_sz);

uid_t elasticlave_create(size_t size);
int elasticlave_change(uid_t uid, unsigned long perm);
int elasticlave_unmap(void* vaddr);
void* elasticlave_map(uid_t uid);
int elasticlave_destroy(uid_t uid);

}  // namespace Keystone

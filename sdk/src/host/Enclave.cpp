//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Enclave.hpp"
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>
extern "C" {
#include "./keystone_user.h"
#include "common/sha3.h"
}
#include "ElfFile.hpp"
#include "hash_util.hpp"

namespace Keystone {

#define PAGE_TABLE_PAGES 128
#define MAX_DR_REQUEST_ARGS 8

static int host_fd;

Enclave::Enclave() {
  state = ENCLAVE_STATE_INVALID;
  runtimeFile = NULL;
  enclaveFile = NULL;
  new_mem_handler = NULL;
  custom = NULL;
  target_call_id = (unsigned long)-1;
  region_n = 0;
}

Enclave::~Enclave() {
  if (runtimeFile) delete runtimeFile;
  if (enclaveFile) delete enclaveFile;
  destroy();
  if (custom) free(custom); // now assuming that cusom is malloced
}

uint64_t
calculate_required_pages(uint64_t eapp_sz, uint64_t rt_sz) {
  uint64_t req_pages = 0;

  req_pages += ceil(eapp_sz / PAGE_SIZE);
  req_pages += ceil(rt_sz / PAGE_SIZE);

  /* FIXME: calculate the required number of pages for the page table.
   * We actually don't know how many page tables the enclave might need,
   * because the SDK never knows how its memory will be aligned.
   * Ideally, this should be managed by the driver.
   * For now, we naively allocate enough pages so that we can temporarily get
   * away from this problem.
   * 15 pages will be more than sufficient to cover several hundreds of
   * megabytes of enclave/runtime. */
  req_pages += PAGE_TABLE_PAGES;
  return req_pages;
}

Error
Enclave::loadUntrusted() {
  uintptr_t va_start = ROUND_DOWN(params.getUntrustedMem(), PAGE_BITS);
  vaddr_t va_start_u = ROUND_UP(params.getUntrustedMem() + (params.getUntrustedSize() >> 1), PAGE_BITS);
  uintptr_t va_end   = ROUND_UP(params.getUntrustedEnd(), PAGE_BITS);

  while (va_start < va_end) {
    if (!pMemory->allocPage(va_start, utm_free_list, va_start < va_start_u ? UTM_FULL : UTM_FULL_U)) {
      return Error::PageAllocationFailure;
    }
    utm_free_list += PAGE_SIZE;
    va_start += PAGE_SIZE;
  }
  return Error::Success;
}

/* This function will be deprecated when we implement freemem */
bool
Enclave::initStack(uintptr_t start, size_t size, bool is_rt) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };
  uintptr_t high_addr = ROUND_UP(start, PAGE_BITS);
  uintptr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
  int stk_pages = (high_addr - va_start_stk) / PAGE_SIZE;

  for (int i = 0; i < stk_pages; i++) {
    if (!pMemory->allocPage(
            va_start_stk, (uintptr_t)nullpage, // TODO epm_free_list instead of nullptr?
            (is_rt ? RT_NOEXEC : USER_NOEXEC)))
      return false;

    va_start_stk += PAGE_SIZE;
    epm_free_list += PAGE_SIZE;
  }

  return true;
}

bool
Enclave::mapElf(ElfFile* elf) {
  uintptr_t va;

  assert(elf);

  size_t num_pages =
      ROUND_DOWN(elf->getTotalMemorySize(), PAGE_BITS) / PAGE_SIZE;
  va = elf->getMinVaddr();

  if (pMemory->epmAllocVspace(va, num_pages) != num_pages) {
    ERROR("failed to allocate vspace\n");
    return false;
  }

  return true;
}

Error
Enclave::loadElf(ElfFile* elf) {
  static char nullpage[PAGE_SIZE] = {0,};

  unsigned int mode = elf->getPageMode();

  size_t num_pages = ROUND_DOWN(elf->getTotalMemorySize(), PAGE_BITS) / PAGE_SIZE;
  vaddr_t va_real = (vaddr_t)pMemory->ReadMem((vaddr_t)epm_free_list, num_pages << PAGE_BITS);
  vaddr_t va_elf = elf->getMinVaddr();
  memset((void*)va_real, 0, num_pages << PAGE_BITS);

  for (unsigned int i = 0; i < elf->getNumProgramHeaders(); i++) {
    if (elf->getProgramHeaderType(i) != PT_LOAD) {
      continue;
    }

    uintptr_t start = elf->getProgramHeaderVaddr(i);
    uintptr_t file_end = start + elf->getProgramHeaderFileSize(i);
    uintptr_t memory_end = start + elf->getProgramHeaderMemorySize(i);
    char* src = reinterpret_cast<char*>(elf->getProgramSegment(i));
    uintptr_t va = start, pa = start - va_elf + epm_free_list;

    /* FIXME: This is a temporary fix for loading iozone binary
     * which has a page-misaligned program header. */
    if (!IS_ALIGNED(va, PAGE_SIZE)) {
      size_t length = PAGE_UP(va) - va;
      if (!pMemory->allocPage(PAGE_DOWN(va), PAGE_DOWN(pa), mode))
        return Error::PageAllocationFailure;
      va += length;
      pa += length;
    }

    /* first load all pages that do not include .bss segment */
    while (va + PAGE_SIZE <= file_end) {
      if (!pMemory->allocPage(va, pa, mode))
        return Error::PageAllocationFailure;
      va += PAGE_SIZE;
      pa += PAGE_SIZE;
    }

    /* next, load the page that has both initialized and uninitialized segments
     */
    if (va < file_end) {
      if (!pMemory->allocPage(va, pa, mode))
        return Error::PageAllocationFailure;
      va += PAGE_SIZE;
      pa += PAGE_SIZE;
    }

    /* finally, load the remaining .bss segments */
    while (va < memory_end) {
      if (!pMemory->allocPage(va, pa, mode))
        return Error::PageAllocationFailure;
      va += PAGE_SIZE;
      pa += PAGE_SIZE;
    }
    if(src != NULL)
      memcpy((void*)(start - va_elf + va_real), src, 
          elf->getProgramHeaderFileSize(i));
  }

  epm_free_list += num_pages << PAGE_BITS;

  return Error::Success;
}

Error
Enclave::validate_and_hash_enclave(struct runtime_params_t args) {
  hash_ctx_t hash_ctx;
  int ptlevel = RISCV_PGLEVEL_TOP;

  hash_init(&hash_ctx);

  // hash the runtime parameters
  hash_extend(&hash_ctx, &args, sizeof(struct runtime_params_t));

  uintptr_t runtime_max_seen = 0;
  uintptr_t user_max_seen = 0;

  // hash the epm contents including the virtual addresses
  int valid = pMemory->validateAndHashEpm(
      &hash_ctx, ptlevel, reinterpret_cast<pte*>(pMemory->getRootPageTable()),
      0, 0, &runtime_max_seen, &user_max_seen);

  if (valid == -1) {
    return Error::InvalidEnclave;
  }

  hash_finalize(hash, &hash_ctx);

  return Error::Success;
}

bool
Enclave::initFiles(const char* eapppath, const char* runtimepath) {
  if (runtimeFile || enclaveFile) {
    ERROR("ELF files already initialized");
    return false;
  }

  runtimeFile = new ElfFile(runtimepath);
  enclaveFile = new ElfFile(eapppath);

  if (!runtimeFile->initialize(true)) {
    ERROR("Invalid runtime ELF\n");
    destroy();
    return false;
  }

  if (!enclaveFile->initialize(false)) {
    ERROR("Invalid enclave ELF\n");
    destroy();
    return false;
  }

  if (!runtimeFile->isValid()) {
    ERROR("runtime file is not valid");
    destroy();
    return false;
  }
  if (!enclaveFile->isValid()) {
    ERROR("enclave file is not valid");
    destroy();
    return false;
  }

  return true;
}

bool
Enclave::prepareEnclave(uintptr_t alternatePhysAddr) {
  uint64_t minPages;
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE;
  minPages += calculate_required_pages(
      enclaveFile->getTotalMemorySize(), runtimeFile->getTotalMemorySize());

  if (params.isSimulated()) {
    pMemory->init(0, 0, minPages);
    return true;
  }

  /* Call Enclave Driver */
  if (pDevice->create(minPages) != Error::Success) {
    return false;
  }

  /* We switch out the phys addr as needed */
  uintptr_t physAddr;
  if (alternatePhysAddr) {
    physAddr = alternatePhysAddr;
  } else {
    physAddr = pDevice->getPhysAddr();
  }

  pMemory->init(pDevice, physAddr, minPages);
  return true;
}

Error
Enclave::init(const char* eapppath, const char* runtimepath, Params _params) {
  return this->init(eapppath, runtimepath, _params, (uintptr_t)0);
}

Error
Enclave::init(
    const char* eapppath, const char* runtimepath, Params _params,
    uintptr_t alternatePhysAddr) {
  params = _params;

  if (params.isSimulated()) {
    pMemory = new SimulatedEnclaveMemory();
    pDevice = new MockKeystoneDevice();
  } else {
    pMemory = new PhysicalEnclaveMemory();
    pDevice = new KeystoneDevice();
  }

  if (!initFiles(eapppath, runtimepath)) {
    return Error::FileInitFailure;
  }

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  if (!prepareEnclave(alternatePhysAddr)) {
    destroy();
    return Error::DeviceError;
  }

  if (!mapElf(runtimeFile)) {
    destroy();
    return Error::VSpaceAllocationFailure;
  }

  pMemory->startRuntimeMem();

  if (loadElf(runtimeFile) != Error::Success) {
    ERROR("failed to load runtime ELF");
    destroy();
    return Error::ELFLoadFailure;
  }

  if (!mapElf(enclaveFile)) {
    destroy();
    return Error::VSpaceAllocationFailure;
  }

  pMemory->startEappMem();

  if (loadElf(enclaveFile) != Error::Success) {
    ERROR("failed to load enclave ELF");
    destroy();
    return Error::ELFLoadFailure;
  }

/* initialize stack. If not using freemem */
#ifndef USE_FREEMEM
  if (!initStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0)) {
    ERROR("failed to init static stack");
    destroy();
    return Error::PageAllocationFailure;
  }
#endif /* USE_FREEMEM */

  uintptr_t utm_free;
  utm_free = pMemory->allocUtm(params.getUntrustedSize());

  if (!utm_free) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  if (loadUntrusted() != Error::Success) {
    ERROR("failed to load untrusted");
  }

  struct runtime_params_t runtimeParams;
  runtimeParams.runtime_entry =
      reinterpret_cast<uintptr_t>(runtimeFile->getEntryPoint());
  runtimeParams.user_entry =
      reinterpret_cast<uintptr_t>(enclaveFile->getEntryPoint());
  runtimeParams.untrusted_ptr =
      reinterpret_cast<uintptr_t>(params.getUntrustedMem());
  runtimeParams.untrusted_size =
      reinterpret_cast<uintptr_t>(params.getUntrustedSize());

  pMemory->startFreeMem();

  /* TODO: This should be invoked with some other function e.g., measure() */
  if (params.isSimulated()) {
    validate_and_hash_enclave(runtimeParams);
  }

  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), runtimeParams) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return Error::DeviceMemoryMapError;
  }
  //}

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  enclaveFile = NULL;
  runtimeFile = NULL;

  performance_stats_init(&run_stats);

  futex_initialised = false;

  state = ENCLAVE_STATE_INITIALISED;

  return Error::Success;
}

bool
Enclave::mapUntrusted(size_t size) {
  if (size == 0) {
    return true;
  }

  shared_buffer = pDevice->map(0, size);
  memset((void*)shared_buffer, 0, size);

  if (shared_buffer == NULL) {
    return false;
  }

  // untrusted_start = (vaddr_t)shared_buffer; // TODO change??? delete??? not in class currently

  shared_buffer_size = size >> 1;

  o_shared_buffer = (void*)((uintptr_t)shared_buffer + shared_buffer_size);
  o_shared_buffer_size = shared_buffer_size;

  return true;
}

Error
Enclave::destroy() {
  if (enclaveFile) {
    delete enclaveFile;
    enclaveFile = NULL;
  }

  if (runtimeFile) {
    delete runtimeFile;
    runtimeFile = NULL;
  }

  return pDevice->destroy();
}

void Keystone::process_new_memory_region(uintptr_t size) {
  void* vaddr = pDevice->map(0, size);
  if (new_mem_handler)
      new_mem_handler(vaddr);
}

// TODO change to using pDevice->resume??
Error Keystone::runOnce(int* ret_code) {
  int ret;

  if(state == ENCLAVE_STATE_INITIALISED){
    run_args.eid = eid;
    run_args.dr_request_resp0 = 0;
    run_args.dr_request_resp1 = 0;
    run_args.dr_request_args = (__u64)dr_request_args;

    performance_check_start(&run_stats);
    ret = ioctl(fd, KEYSTONE_IOC_RUN_ENCLAVE, &run_args);
    performance_check_end(&run_stats);
    performance_count(&run_stats);
  } else if(state == ENCLAVE_STATE_LAUNCHED) {
    performance_check_start(&run_stats);
    ret = ioctl(fd, KEYSTONE_IOC_RESUME_ENCLAVE, &run_args);
    performance_check_end(&run_stats);
    performance_count(&run_stats);
  } else if(state == ENCLAVE_STATE_BLOCKED){
    if (ocall_dispatcher != NULL) {
      int cont = !ocall_dispatcher->dispatchBlocked(this, getSharedBuffer());
      if(!cont)
        return KEYSTONE_SUCCESS;
      state = ENCLAVE_STATE_LAUNCHED;
      performance_check_start(&run_stats);
      ret = ioctl(fd, KEYSTONE_IOC_RESUME_ENCLAVE, &run_args);
      performance_check_end(&run_stats);
      performance_count(&run_stats);
    } else
      return KEYSTONE_SUCCESS;
  } else{
    return KEYSTONE_ERROR;
  }

    state = ENCLAVE_STATE_LAUNCHED;

  int cont;
  while(ret) {
    cont = 0;
    switch(ret) {
      case KEYSTONE_ENCLAVE_EDGE_CALL_HOST:
        if(ocall_dispatcher != NULL) {
          cont = !ocall_dispatcher->dispatch(this, getSharedBuffer()); // TODO: cont decided by the dispatch function
          if(!cont) { // need to block until future
            state = ENCLAVE_STATE_BLOCKED;
          }
        } else
          cont = 1;
        break;
      case KEYSTONE_ENCLAVE_CALL_RETURN:
      case KEYSTONE_ENCLAVE_INTERRUPTED:
      case KEYSTONE_ENCLAVE_YIELDED:
        cont = 0;
        break;
      case KEYSTONE_ENCLAVE_NEW_MEM_REGION:
        process_new_memory_region(dr_request_args[0]);
        cont = 1;
        break;
      default:
        destroy();
        ERROR("failed to run enclave - ioctl() failed: %d", ret);
        return KEYSTONE_ERROR;
    }

    if(!cont)
      break;
    performance_check_start(&run_stats);
    ret = ioctl(fd, KEYSTONE_IOC_RESUME_ENCLAVE, &run_args);
    performance_check_end(&run_stats);
    performance_count(&run_stats);
  }

  if(!ret)
    state = ENCLAVE_STATE_ENDED;

  *ret_code = ret;
  return KEYSTONE_SUCCESS;
}

// TODO change to use runOnce??
Error
Enclave::run(uintptr_t* retval) {
  if (params.isSimulated()) {
    return Error::Success;
  }

  Error ret = pDevice->run(retval);
  while (ret == Error::EdgeCallHost || ret == Error::EnclaveInterrupted) {
    /* enclave is stopped in the middle. */
    if (ret == Error::EdgeCallHost && oFuncDispatch != NULL) {
      oFuncDispatch(getSharedBuffer());
    }
    ret = pDevice->resume(retval);
  }

  if (ret != Error::Success) {
    ERROR("failed to run enclave - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  return Error::Success;
}

Error Keystone::call(unsigned long call_id, void* data, size_t data_len, void* return_buffer, size_t return_len){
    return call_with_stats(call_id, data, data_len, return_buffer, return_len, &ecall_stats);
}

Error Keystone::call_with_stats(unsigned long call_id, void* data, size_t data_len, void* return_buffer, size_t return_len, struct ecall_stats* stats) {
  if(params.isSimulated())
    return KEYSTONE_ERROR;

  struct shared_region shared_region;
  shared_region.shared_start = (uintptr_t)o_shared_buffer;
  shared_region.shared_len = o_shared_buffer_size;
  void* shared_buffer = o_shared_buffer;
  size_t shared_buffer_size = o_shared_buffer_size;

  int ret;
  struct edge_call* edge_call = (struct edge_call*)shared_buffer;
  uintptr_t buffer_data_start = edge_call_data_ptr(&shared_region);

  if (data_len > (shared_buffer_size - (buffer_data_start - (uintptr_t)shared_buffer))) {
    return KEYSTONE_ERROR;
  }

  if(call_id == target_call_id)
    performance_check_start(&stats->args_copy_stats);
  memcpy((void*)buffer_data_start, (void*)data, data_len);
  if (call_id == target_call_id) {
    performance_check_end(&stats->args_copy_stats);
    performance_count(&stats->args_copy_stats);
    performance_count_data(&stats->args_copy_stats, data_len);
  }

  if(edge_call_setup_call(edge_call, (void*)buffer_data_start, data_len, &shared_region) != 0){
    return KEYSTONE_ERROR;
  }

  // TODO change to use pDevice?
  edge_call->call_id = call_id; // only finally set the call_id
  do {
    if (runOnce(&ret) != KEYSTONE_SUCCESS) {
      return KEYSTONE_ERROR;
    }
  } while(ret && ret != KEYSTONE_ENCLAVE_CALL_RETURN);

  if (!ret) {
    return KEYSTONE_ERROR;
  }

  if (edge_call->return_data.call_status != CALL_STATUS_OK) {
    return KEYSTONE_ERROR;
  }

  if( return_len == 0 ) {
    /* Done, no return */
    return KEYSTONE_SUCCESS;
  }

  uintptr_t return_ptr;
  size_t ret_len_untrusted;
  if(edge_call_ret_ptr(edge_call, &return_ptr, &ret_len_untrusted, &shared_region) != 0){
    return KEYSTONE_ERROR;
  }

  if(ret_len_untrusted < return_len)
    return_len = ret_len_untrusted;

  if(call_id == target_call_id)
    performance_check_start(&stats->retval_copy_stats);
  memcpy(return_buffer, (void*)return_ptr, return_len);
  if (call_id == target_call_id) {
    performance_check_end(&stats->retval_copy_stats);
    performance_count(&stats->retval_copy_stats);
    performance_count_data(&stats->retval_copy_stats, return_len);
  }

  return KEYSTONE_SUCCESS;
}

void*
Enclave::getSharedBuffer() {
  return shared_buffer;
}

size_t
Enclave::getSharedBufferSize() {
  return shared_buffer_size;
}

enum enclave_state Keystone::getState() const{
    return state;
}

Error
Enclave::registerOcallDispatch(EdgeCallDispatcher* dispatcher) {
  dispatcher->setupSharedRegion((uintptr_t)shared_buffer, shared_buffer_size);
  ocall_dispatcher = dispatcher;
  return Error::Success;
}

Error Keystone::registerNewMemHandler(NewMemHandler handler){
    new_mem_handler = handler;
    return KEYSTONE_SUCCESS;
}

int Keystone::getSID() const{
    int ret= ioctl(fd, KEYSTONE_IOC_GET_ENCLAVE_ID, &eid);
    return ret;
}

Error EnclaveGroup::run(){
    int i, ret;
    bool cont = true;
    while(cont) {
        cont = false;
        for(i = 0; i < enclave_n; i++){
            if(enclaves[i]->getState() != ENCLAVE_STATE_ENDED &&
                    enclaves[i]->getState() != ENCLAVE_STATE_INVALID){
                cont = true;
                enclaves[i]->runOnce(&ret);
            }
        }
    }
    return KEYSTONE_SUCCESS;
}


uid_t elasticlave_create(size_t size){
    uid_t uid;
    struct keystone_ioctl_elasticlave_create params = {
        .size = size,
        .uid = &uid
    };
    int ret = ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_CREATE, &params);
    if (ret == -1)
        return 0;
    return uid;
}

int elasticlave_change(uid_t uid, unsigned long perm) {
    struct keystone_ioctl_elasticlave_change params = {
        .uid = (__u64)uid,
        .perm = (__u64)perm
    };
    return ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_CHANGE, &params);
}

int elasticlave_destroy(uid_t uid){
    return ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_DESTROY, &uid);
}

void* elasticlave_map(uid_t uid){
    uintptr_t size;
    struct keystone_ioctl_elasticlave_map params = {
        .uid = uid,
        .size = (__u64)&size
    };
    int ret = ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_MAP, &params);
    if(ret == -1)
        return NULL;
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, host_fd, 0);
}

int elasticlave_unmap(void* vaddr){
    uintptr_t size;
    struct keystone_ioctl_elasticlave_unmap params = {
        .vaddr = (__u64)vaddr,
        .size = (__u64)&size
    };
    int ret = ioctl(host_fd, KEYSTONE_IOC_ELASTICLAVE_UNMAP, &params);
    if(ret)
        return ret;
    return munmap(vaddr, size);
}

void Keystone::set_target_call(unsigned long target) {
    target_call_id = target;
}

void Keystone::print_call_stats() {
    print_ecall_stats(&ecall_stats);
}

bool keystone_init(){
    host_fd = open(KEYSTONE_DEV_PATH, O_RDWR);
    if (host_fd < 0) {
        PERROR("cannot open device file");
        return false;
    }
    return true;
}

int Keystone::print_sm_stats(struct enclave_stats* stats){
    struct keystone_ioctl_sm_stats ioc_data;
    ioc_data.eid = eid;
    ioc_data.stats = stats;
    int ret = ioctl(fd, KEYSTONE_IOC_SM_PRINT_STATS, &ioc_data);
    return ret;
}

int Keystone::print_rt_stats(struct enclave_rt_stats* rt_stats){
    struct keystone_ioctl_rt_stats ioc_data;
    ioc_data.eid = eid;
    ioc_data.rt_stats = rt_stats;
    int ret = ioctl(fd, KEYSTONE_IOC_SM_PRINT_RT_STATS, &ioc_data);
    return ret;
}

struct performance_stats Keystone::get_run_stats() const{
    return run_stats;
}

Error Keystone::elasticlave_transfer(uid_t uid){
    struct keystone_ioctl_elasticlave_transfer params = {
        .uid = uid,
        .eid = (__u64)this->eid
    };
    int ret = ioctl(fd, KEYSTONE_IOC_ELASTICLAVE_TRANSFER, &params);
    return ret ? KEYSTONE_ERROR : KEYSTONE_SUCCESS;
}

Error Keystone::elasticlave_share(uid_t uid, unsigned long perm){
    struct keystone_ioctl_elasticlave_share params = {
        .uid = uid,
        .perm = (__u64)perm,
        .eid = (__u64)this->eid
    };
    int ret = ioctl(fd, KEYSTONE_IOC_ELASTICLAVE_SHARE, &params);
    return ret ? KEYSTONE_ERROR : KEYSTONE_SUCCESS;
}

void* Keystone::get_region_buffer(uid_t uid) const{
    int i;
    for(i = 0; i < region_n; i++) {
        if (region_uids[i] == uid)
            return region_bufs[i];
    }
    return NULL;
}

void Keystone::add_region_buffer(uid_t uid, void* buf){
    region_uids[region_n] = uid;
    region_bufs[region_n] = buf;
    ++region_n;
}








}  // namespace Keystone

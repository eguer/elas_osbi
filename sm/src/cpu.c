//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "cpu.h"
#include "enclave.h"
#include <sbi/riscv_asm.h>

static struct cpu_state cpus[MAX_HARTS] = {0,};

int cpu_is_enclave_context()
{
  return cpus[csr_read(mhartid)].is_enclave;
}

int cpu_get_enclave_id()
{
  return cpus[csr_read(mhartid)].eid;
}

void cpu_enter_enclave_context(unsigned int eid)
{
  cpus[csr_read(mhartid)].is_enclave = 1;
  cpus[csr_read(mhartid)].eid = eid;
}

void cpu_exit_enclave_context()
{
  cpus[csr_read(mhartid)].is_enclave = 0;
}

int cpu_is_enclave_context_idx(int i){
  return cpus[i].is_enclave != 0;
}

int cpu_get_enclave_id_idx(int i){
  return encl_index(encl_get(cpus[i].eid));
}

void cpu_set_to_terminate(int to_terminate){
  cpus[csr_read(mhartid)].to_terminate = to_terminate;
}

int cpu_is_to_terminate(){
  return cpus[csr_read(mhartid)].to_terminate;
}
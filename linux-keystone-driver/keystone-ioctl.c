//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "keystone.h"
#include "keystone-sbi.h"
#include "keystone_user.h"
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/list.h>

static int __keystone_destroy_enclave(unsigned int ueid);

static int keystone_create_enclave(struct file *filep, unsigned long arg)
{
  /* create parameters */
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;

  struct enclave *enclave;
  enclave = create_enclave(enclp->min_pages);

  if (enclave == NULL) {
    return -ENOMEM;
  }

  /* Pass base page table */
  enclp->pt_ptr = __pa(enclave->epm->root_page_table);
  enclp->epm_size = enclave->epm->size; // this epm size is 2^count (the actual contiguous physical memory reserved)


  /* allocate UID */
  enclp->eid = enclave_idr_alloc(enclave);

  filep->private_data = (void *) enclp->eid;

  return 0;
}

int keystone_get_enclave_id(unsigned long arg){
  unsigned long ueid = *(unsigned long*)arg;
  struct enclave* enclave = get_enclave_by_id(ueid);
  if (enclave == NULL)
	  return -1;
  return enclave->eid;
}

static int keystone_sm_print_stats(unsigned long arg){
  struct keystone_ioctl_sm_stats *stats = (struct keystone_ioctl_sm_stats *) arg;
  unsigned long ueid = stats->eid;
  struct enclave* enclave = get_enclave_by_id(ueid);
  if(enclave == NULL)
	  return -1;
  struct enclave_stats tmp_stats;
  uintptr_t tmp_stats_paddr = __pa((uintptr_t)&tmp_stats);
  struct sbiret ret = sbi_sm_print_stats(enclave->eid, tmp_stats_paddr);
  if (ret.error)
	  return ret.error;
  copy_to_user(stats->stats, &tmp_stats, sizeof(struct enclave_stats));

  return 0;
}

static int keystone_sm_print_rt_stats(unsigned long arg){
  struct keystone_ioctl_rt_stats *stats = (struct keystone_ioctl_rt_stats *) arg;
  unsigned long ueid = stats->eid;
  struct enclave* enclave = get_enclave_by_id(ueid);
  if(enclave == NULL)
	  return -1;
  struct enclave_rt_stats tmp_stats;
  uintptr_t tmp_stats_paddr = __pa((uintptr_t)&tmp_stats);
  struct sbiret ret = sbi_sm_print_rt_stats(enclave->eid, tmp_stats_paddr);
  if (ret.error)
	  return ret.error;
  copy_to_user(stats->rt_stats, &tmp_stats, sizeof(struct enclave_rt_stats));

  return 0;
}

static int keystone_finalize_enclave(unsigned long arg)
{
  struct sbiret ret;
  struct enclave *enclave;
  struct utm *utm;
  struct keystone_sbi_create_t create_args;

  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;

  enclave = get_enclave_by_id(enclp->eid);
  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  enclave->is_init = false;

  /* SBI Call */
  create_args.epm_region.paddr = enclave->epm->pa;
  create_args.epm_region.size = enclave->epm->size;

  utm = enclave->utm;

  if(utm) {
    create_args.utm_region.paddr = __pa(utm->ptr);
    create_args.utm_region.size = utm->size;
    create_args.utm_region.mode = REGION_MODE_R | REGION_MODE_W;
  } else {
    create_args.utm_region.paddr = 0;
    create_args.utm_region.size = 0;
    create_args.utm_region.mode = 0;
  }

  // physical addresses for runtime, user, and freemem
  create_args.runtime_paddr = enclp->runtime_paddr;
  create_args.user_paddr = enclp->user_paddr;
  create_args.free_paddr = enclp->free_paddr;

  create_args.params = enclp->params; // runtime params

  // SM will write the eid to struct enclave.eid
  create_args.eid_pptr = (unsigned int *) __pa(&enclave->eid);


  // set up the PMP regions for utm and epm
  // computing the measurement
  ret = sbi_sm_create_enclave(&create_args);
  if (ret.error) {
    keystone_err("keystone_create_enclave: SBI call failed with error codd %ld\n", ret.error);
    goto error_destroy_enclave;
  }

  enclave->eid = ret.value;

  return 0;

error_destroy_enclave:
  /* This can handle partial initialization failure */
  destroy_enclave(enclave);

  return -EINVAL;

}

static int process_host_response(struct enclave* enclave, uintptr_t host_resp0, uintptr_t host_resp1, uintptr_t* resp0, uintptr_t* resp1){
  int ret;
  switch(enclave->request.type){
    case DR_REQUEST_NONE:
		ret = 0;
		break;
	case DR_REQUEST_NEW_MEM_REGION:
		if(enclave->recent_shm && enclave->recent_shm->va){
			*resp0 = (uintptr_t)enclave->recent_shm->pa;
			*resp1 = enclave->recent_shm->va;
			enclave->request.type = DR_REQUEST_NONE;
			ret = 0;
		} else
			ret = 1;
		break;
	default:
		ret = 1;
		keystone_err("bad request type\n");
  }
  return ret;
}

static void setup_dr_request(struct enclave* enclave, uintptr_t dr_request, int* request_code, enum dr_request_type request_type, int num, ...){
	enclave->request.type = request_type;
	*request_code = ENCLAVE_NEW_MEM_REGION;

	va_list arg_list;
	va_start(arg_list, num);
	
	int i;

	for(i = 0; i < num; i ++){
		enclave->request.args[i] = va_arg(arg_list, uintptr_t);
	}

	va_end(arg_list);

	copy_to_user((void*)dr_request, enclave->request.args, num * sizeof(uintptr_t));
}


/**
 * Returns: 
 *	non-zero: need to get back to security monitor
 *	zero: need to get back to host application
 * */
static int process_sm_request(struct enclave* enclave, long* request_code, uintptr_t* request_args, uintptr_t* resp0, uintptr_t* resp1, uintptr_t dr_request){
  int ret = 1;
  switch(*request_code){
    case SBI_SM_REQUEST_ELASTICLAVE_CREATE:
      *resp0 = enclave_elasticlave_create(enclave, request_args[0]);
	  /*setup_dr_request(enclave, dr_request, request_code, DR_REQUEST_NEW_MEM_REGION, 1, request_args[0]);*/
	  // Don't notify the host for now
	  ret = 1;
      break;
	case SBI_SM_REQUEST_ELASTICLAVE_DESTROY:
	  destroy_shm_by_pa(request_args[0]);
	  ret = 1;
	  break;
	case ENCLAVE_INTERRUPTED:
	  ret = 0;
	  break;
  default:
	  ret = 0;
  }
  return ret;
}

static int keystone_run_enclave(unsigned long arg)
{
  struct sbiret ret;
  unsigned long ueid;
  struct enclave* enclave;
  struct keystone_ioctl_run_enclave *run = (struct keystone_ioctl_run_enclave*) arg;
  uintptr_t dr_request_args = (uintptr_t)run->dr_request_args;
  uintptr_t request_args[SBI_SM_REQUEST_ARGS_LIM];

  ueid = run->eid;
  enclave = get_enclave_by_id(ueid);

  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  ret = sbi_sm_run_enclave(enclave->eid, __pa((uintptr_t)request_args));

  uintptr_t resp0 = 0, resp1 = 0;
  while (process_sm_request(enclave, &(ret.error), request_args, &resp0, &resp1, dr_request_args))
    ret = sbi_sm_resume_enclave(enclave->eid, __pa((uintptr_t)request_args), resp0, resp1);

  run->error = ret.error;
  run->value = ret.value;

  return 0;
}

int utm_init_ioctl(struct file *filp, unsigned long arg)
{
  int ret = 0;
  struct utm *utm;
  struct enclave *enclave;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;
  long long unsigned untrusted_size = enclp->params.untrusted_size;

  enclave = get_enclave_by_id(enclp->eid);

  if(!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  utm = kmalloc(sizeof(struct utm), GFP_KERNEL);
  if (!utm) {
    ret = -ENOMEM;
    return ret;
  }

  ret = utm_init(utm, untrusted_size);

  /* prepare for mmap */
  enclave->utm = utm;
  enclave->epm_mapped = true;

  enclp->utm_free_ptr = __pa(utm->ptr);

  return ret;
}


static int keystone_destroy_enclave(struct file *filep, unsigned long arg)
{
  int ret;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave *) arg;
  unsigned long ueid = enclp->eid;

  ret = __keystone_destroy_enclave(ueid);
  if (!ret) {
    filep->private_data = NULL;
  }
  return ret;
}

struct enclave_shm {
	uintptr_t pa;
	uintptr_t size;
};

struct enclave_shm_list {
	unsigned int shm_count;
	struct enclave_shm shms[16];
};

static int __keystone_destroy_enclave(unsigned int ueid)
{
  struct sbiret ret;
  struct enclave *enclave;
  struct enclave_shm_list enclave_shm_list;
  enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  ret = sbi_sm_destroy_enclave(enclave->eid, __pa((uintptr_t)&enclave_shm_list));
  if (ret.error) {
    keystone_err("fatal: cannot destroy enclave: SBI failed with error code %ld\n", ret.error);
    return -EINVAL;
  }
  
  int i;
  for (i = 0; i < enclave_shm_list.shm_count; i ++) {
	  destroy_shm_by_pa(enclave_shm_list.shms[i].pa);
  }

  destroy_enclave(enclave);
  enclave_idr_remove(ueid);

  return 0;
}

static int keystone_resume_enclave(unsigned long arg)
{
  struct sbiret ret;
  struct keystone_ioctl_run_enclave *resume = (struct keystone_ioctl_run_enclave*) arg;
  unsigned long ueid = resume->eid;
  struct enclave* enclave;
  enclave = get_enclave_by_id(ueid);
  uintptr_t request_args[SBI_SM_REQUEST_ARGS_LIM], scratch = 0;
  uintptr_t dr_request_args = (uintptr_t)resume->dr_request_args;

  if (!enclave)
  {
    keystone_err("invalid enclave id\n");
    return -EINVAL;
  }

  uintptr_t resp0 = 0, resp1 = 0;


  if (process_host_response(enclave, (uintptr_t)resume->dr_request_resp0, (uintptr_t)resume->dr_request_resp1, &resp0, &resp1)){
	keystone_err("host response invalid\n");
	return -EINVAL;
  }

  ret = sbi_sm_resume_enclave(enclave->eid, __pa((uintptr_t)request_args), resp0, resp1);

  while (process_sm_request(enclave, &(ret.error), request_args, &resp0, &resp1, dr_request_args))
    ret = sbi_sm_resume_enclave(enclave->eid, __pa((uintptr_t)request_args), resp0, resp1);

  resume->error = ret.error;
  resume->value = ret.value;

  return 0;
}

static int keystone_elasticlave_change(unsigned long arg){
	struct keystone_ioctl_elasticlave_change* elasticlave_change_arg = (struct keystone_ioctl_elasticlave_change*)arg;
	struct sbiret ret = sbi_sm_elasticlave_change(elasticlave_change_arg->uid, elasticlave_change_arg->perm);
	return ret.error;
}

static int keystone_elasticlave_create(unsigned long arg){
	struct keystone_ioctl_elasticlave_create* params = (struct keystone_ioctl_elasticlave_create*)arg;
	uintptr_t pa = enclave_elasticlave_create(&host_enclave, params->size);
	if (!pa)
		return -1;
	uid_t uid;
	struct sbiret ret = sbi_sm_elasticlave_create(pa, params->size, __pa((uintptr_t)&uid));
	if (ret.error) {
		destroy_shm_by_pa(pa);
		return -1;
	}
	return copy_to_user((uid_t*)params->uid, &uid, sizeof(uid_t));
}

static int keystone_elasticlave_map(unsigned long arg) {
	struct keystone_ioctl_elasticlave_map* params = (struct keystone_ioctl_elasticlave_map*)arg;
	uid_t uid = params->uid;
	uintptr_t addr, size;
	uintptr_t pa_addr = __pa((uintptr_t)&addr),
			  pa_size = __pa((uintptr_t)&size);
	struct sbiret ret = sbi_sm_elasticlave_map(uid, pa_addr, pa_size);
	if (ret.error)
		return ret.error;
	map_pending = 1;
	map_pa = addr;
	map_size = size;
	map_uid = uid;

	return copy_to_user((uintptr_t*)params->size, &size, sizeof(uintptr_t));
}

static int keystone_elasticlave_unmap(unsigned long arg) {
	struct keystone_ioctl_elasticlave_unmap* params = (struct keystone_ioctl_elasticlave_unmap*)arg;
	uintptr_t va = (uintptr_t)params->vaddr;
	int i;
	for(i = 0; i < mem_mappings_n && mem_mappings[i].va != va; i ++);
	if(i == mem_mappings_n)
		return -1;
	struct sbiret ret = sbi_sm_elasticlave_unmap((uintptr_t)mem_mappings[i].uid);
	if (ret.error)
		return ret.error;
	size_t size = mem_mappings[i].size;
	for (; i < mem_mappings_n - 1; i ++)
		mem_mappings[i] = mem_mappings[i + 1];
	-- mem_mappings_n;
	return copy_to_user((__u64*)params->size, &size, sizeof(__u64));
}

static int keystone_elasticlave_destroy(unsigned long arg) {
	uid_t uid = *(uid_t*)arg;
  struct sbiret ret = sbi_sm_elasticlave_destroy(uid);
	return ret.error;
}

static int keystone_elasticlave_transfer(unsigned long arg) {
	struct keystone_ioctl_elasticlave_transfer* params = 
		(struct keystone_ioctl_elasticlave_transfer*)arg;
	struct sbiret ret =  sbi_sm_elasticlave_transfer((uintptr_t)params->uid,
			(uintptr_t)params->eid);
  return ret.error;
}

static int keystone_elasticlave_share(unsigned long arg){
	struct keystone_ioctl_elasticlave_share* params = 
		(struct keystone_ioctl_elasticlave_share*)arg;
	struct sbiret ret =  sbi_sm_elasticlave_share((uintptr_t)params->uid,
			(uintptr_t)params->eid,
			(uintptr_t)params->perm);
  return ret.error;
}

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  long ret;
  char data[512];

  size_t ioc_size;

  if (!arg)
    return -EINVAL;

  ioc_size = _IOC_SIZE(cmd);
  ioc_size = ioc_size > sizeof(data) ? sizeof(data) : ioc_size;


  if (copy_from_user(data,(void __user *) arg, ioc_size))
    return -EFAULT;

  switch (cmd) {
    case KEYSTONE_IOC_CREATE_ENCLAVE:
      ret = keystone_create_enclave(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_FINALIZE_ENCLAVE:
      ret = keystone_finalize_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_DESTROY_ENCLAVE:
      ret = keystone_destroy_enclave(filep, (unsigned long) data);
      break;
    case KEYSTONE_IOC_RUN_ENCLAVE:
      ret = keystone_run_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_RESUME_ENCLAVE:
      ret = keystone_resume_enclave((unsigned long) data);
      break;
    /* Note that following commands could have been implemented as a part of ADD_PAGE ioctl.
     * However, there was a weird bug in compiler that generates a wrong control flow
     * that ends up with an illegal instruction if we combine switch-case and if statements.
     * We didn't identified the exact problem, so we'll have these until we figure out */
    case KEYSTONE_IOC_UTM_INIT:
      ret = utm_init_ioctl(filep, (unsigned long) data);
      break;
	  case KEYSTONE_IOC_GET_ENCLAVE_ID:
	    ret = keystone_get_enclave_id((unsigned long) data);
	    break;
	  case KEYSTONE_IOC_ELASTICLAVE_CHANGE:
	    ret = keystone_elasticlave_change((unsigned long)data);
	    break;
	  case KEYSTONE_IOC_ELASTICLAVE_CREATE:
	    ret = keystone_elasticlave_create((unsigned long)data);
	    break;
	  case KEYSTONE_IOC_ELASTICLAVE_DESTROY:
	    ret = keystone_elasticlave_destroy((unsigned long)data);
	    break;
	  case KEYSTONE_IOC_ELASTICLAVE_MAP:
	    ret = keystone_elasticlave_map((unsigned long)data);
	    break;
	  case KEYSTONE_IOC_ELASTICLAVE_UNMAP:
	    ret = keystone_elasticlave_unmap((unsigned long)data);
	    break;
	  case KEYSTONE_IOC_ELASTICLAVE_TRANSFER:
	    ret = keystone_elasticlave_transfer((unsigned long)data);
	    break;
	  case KEYSTONE_IOC_ELASTICLAVE_SHARE:
	    ret = keystone_elasticlave_share((unsigned long)data);
	    break;
	  case KEYSTONE_IOC_SM_PRINT_STATS:
	    ret = keystone_sm_print_stats((unsigned long)data);
	    break;
	  case KEYSTONE_IOC_SM_PRINT_RT_STATS:
	    ret = keystone_sm_print_rt_stats((unsigned long)data);
	    break;
    default:
      return -ENOSYS;
  }

  if (copy_to_user((void __user*) arg, data, ioc_size))
    return -EFAULT;

  return ret;
}

int keystone_release(struct inode *inode, struct file *file) {
  unsigned long ueid = (unsigned long)(file->private_data);

  /* enclave has been already destroyed */
  if (!ueid) {
    return 0;
  }

  /* We need to send destroy enclave just the eid to close. */
    struct enclave *enclave = get_enclave_by_id(ueid);

  if (!enclave) {
    /* If eid is set to the invalid id, then we do not do anything. */
    return -EINVAL;
  }
  if (enclave->close_on_pexit) {
    return __keystone_destroy_enclave(ueid);
  }
  return 0;
}

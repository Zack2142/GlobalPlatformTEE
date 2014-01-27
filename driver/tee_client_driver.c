/*
 * OpenVirtualization:
 * For additional details and support contact developer@sierraware.com.
 * Additional documentation can be found at www.openvirtualization.org
 *
 * Copyright (C) 2011 SierraWare
 * Copyright (C) 2014 Technicolor
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * GlobalPlatform Trust Execution Environment implemntation using Trustzone
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/slab.h>					// For kmalloc
#include <linux/platform_device.h>
//#include <linux/debugfs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h> 				// For copy_from/to_user
#include <linux/sched.h> 				// For current variable
#include <linux/list.h>
//#include <linux/mutex.h>
//#include <linux/io.h>
//#include <linux/interrupt.h>
#include <linux/wait.h>
#include <asm/cacheflush.h>
//
//
/* Driver dependent includes*/
#include <driver/tee_client_driver_common.h>
#include <driver/tee_client_driver.h>
//#include <otz_common.h>
//#include <otz_id.h>
//#include <smc_id.h>
//sa
//#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
//
//

/**
 * Global variable for device class
 */
static struct class *driver_class;

/**
 * Device <major,minor> info
 */
static dev_t tee_driver_device_no;

/**
 * Global variable for the character device structure
 */
static struct cdev tee_driver_cdev;

//
static u32 cacheline_size;

/**
 * Global variable for the head list of the device file
 */
static teec_dev_file_head_t teec_dev_file_head;

static u32 device_file_cnt = 0;

//static struct otz_smc_cdata otz_smc_cd[NR_CPUS];
//
///**
// * @brief
// *
// * @param in_lock
// */
//static DEFINE_MUTEX(in_lock);

/**
 * @brief Mutex variable to avoid mutual access to send ioctl function
 *
 * @param send_cmd_lock
 */
static DEFINE_MUTEX(send_cmd_lock);

/**
 * @brief Mutex variable to handle smc command mutual exclusion access
 *
 * @param smc_lock
 */
static DEFINE_MUTEX(smc_lock);

/**
 * @brief Mutex variable to protect mutual access to encode command ioctl function
 *
 * @param encode_cmd_lock
 */
static DEFINE_MUTEX(encode_cmd_lock);

///**
// * @brief
// *
// * @param decode_cmd_lock
// */
//static DEFINE_MUTEX(decode_cmd_lock);
//
/**
 * @brief Mutex to handle open session mutual exclusion
 *
 * @param ses_open_lock
 */
static DEFINE_MUTEX(ses_open_lock);

///**
// * @brief
// *
// * @param ses_close_lock
// */
//static DEFINE_MUTEX(ses_close_lock);
//
///**
// * @brief
// *
// * @param mem_free_lock
// */
//static DEFINE_MUTEX(mem_free_lock);
//
///**
// * @brief
// *
// * @param mem_alloc_lock
// */
//static DEFINE_MUTEX(mem_alloc_lock);
//

//
//
///**
// * @brief
// */
//typedef struct otzc_session{
//    struct list_head head;
//    int session_id;
//
//    struct list_head encode_list;
//    struct list_head shared_mem_list;
//} otzc_session;
//

//
///**
// * @brief
// */
//typedef struct otzc_encode{
//
//    struct list_head head;
//
//    int encode_id;
//
//    void* ker_req_data_addr;
//    void* ker_res_data_addr;
//
//    u32  enc_req_offset;
//    u32  enc_res_offset;
//    u32  enc_req_pos;
//    u32  enc_res_pos;
//    u32  dec_res_pos;
//
//    u32  dec_offset;
//
//    struct otz_wait_data wait_data;
//
//    struct otzc_encode_meta *meta;
//} otzc_encode;
//
//
//
///**
// * @brief
// */
//typedef struct otzc_shared_mem{
//
//    struct list_head head;
//    struct list_head s_head;
//
//    void* index;
//
//    void* k_addr;
//    void* u_addr;
//    u32  len;
//} otzc_shared_mem;
//

// Implicit declaration
static int tee_client_prepare_encode(void* private_data,
                                     tee_client_encode_cmd_t *enc,
                                     teec_encode_t **penc_context,
                                     teec_session_t **psession);

/**
 * @brief
 *
 * @param cmd_addr
 *
 * @return
 */
static u32 _tee_smc(u32 cmd_addr)
{
	flush_cache_all();

    register u32 r0 asm("r0") = CALL_TEE_API;
    register u32 r1 asm("r1") = cmd_addr;
    register u32 r2 asm("r2") = TEE_CMD_TYPE_NS_TO_SECURE;
    do {
        asm volatile(
            __asmeq("%0", "r0")
            __asmeq("%1", "r0")
            __asmeq("%2", "r1")
            __asmeq("%3", "r2")
            "smc    #0  @ switch to secure world "
            : "=r" (r0)
            : "r" (r0), "r" (r1), "r" (r2));
    } while (0);

    return r0;
}

///**
// * @brief
// *
// * @param otz_smc handler for secondary cores
// *
// * @return
// */
//static void secondary_otz_smc_handler(void *info)
//{
//	struct otz_smc_cdata *cd = (struct otz_smc_cdata *)info;
//
//	rmb();
//
//	TDEBUG("secondary otz smc handler...");
//
//	cd->ret_val = _otz_smc(cd->cmd_addr);
//	wmb();
//
//	TDEBUG("done smc on primary  ");
//}
//



/**
 * @brief Prepare command before call smc
 *
 * @param svc_id  	- service identifier
 * @param cmd_id  	- command identifier
 * @param context	- session context
 * @param enc_id 	- encoder identifier
 * @param cmd_buf 	- command buffer
 * @param cmd_len 	- command buffer length
 * @param resp_buf 	- response buffer
 * @param resp_len 	- response buffer length
 * @param meta_data
 * @param ret_resp_len
 *
 * @return
 */
static int teec_smc_call(u32 dev_file_id, u32 svc_id, u32 cmd_id,
                    u32 context, u32 enc_id, const void *cmd_buf,
                    size_t cmd_len, void *resp_buf, size_t resp_len,
                    const void *meta_data, int *ret_resp_len,
                    struct tee_wait_data_t* wq, void* arg_lock)
{
    int ret;
    u32 smc_cmd_phys;

    static tee_smc_cmd_t *smc_cmd;

    smc_cmd = (tee_smc_cmd_t*)kmalloc(sizeof(tee_smc_cmd_t),
                                            GFP_KERNEL);
   if(!smc_cmd){
       TERR("kmalloc failed for smc command ");
       ret = -ENOMEM;
       goto out;
   }

    if(ret_resp_len)
        *ret_resp_len = 0;

//    smc_cmd->svc_id = (svc_id << 10) | cmd_id;
    smc_cmd->svc_id = svc_id;
    smc_cmd->src_context = task_tgid_vnr(current);

//    smc_cmd->id = (svc_id << 10) | cmd_id;
    smc_cmd->cmd_id = cmd_id;
    smc_cmd->context = context;
    smc_cmd->enc_id = enc_id;
    smc_cmd->dev_file_id = dev_file_id;
    smc_cmd->req_buf_len = cmd_len;
    smc_cmd->resp_buf_len = resp_len;
    smc_cmd->ret_resp_buf_len = 0;

    if(cmd_buf)
        smc_cmd->req_buf_phys = virt_to_phys((void*)cmd_buf);
    else
        smc_cmd->req_buf_phys = 0;

    if(resp_buf)
        smc_cmd->resp_buf_phys = virt_to_phys((void*)resp_buf);
    else
        smc_cmd->resp_buf_phys = 0;

    if(meta_data)
        smc_cmd->meta_data_phys = virt_to_phys((void*)meta_data);
    else
        smc_cmd->meta_data_phys = 0;

    smc_cmd_phys = virt_to_phys((void*)smc_cmd);

    mutex_lock(&smc_lock);
    ret = _tee_smc(smc_cmd_phys);
    mutex_unlock(&smc_lock);

    if (ret) {
        TERR("smc_call returns error ");
        /*printk("%s  ", otz_strerror(ret));*/
        goto out;
    }

    if(ret_resp_len) {
        *ret_resp_len = smc_cmd->ret_resp_buf_len;
    }

out:
    if(smc_cmd)
        kfree(smc_cmd);
    return ret;
}

///**
// * @brief
// */
//static void otz_client_close_session_for_service(
//                        void* private_data,
//                        otzc_service* temp_svc,
//                        otzc_session *temp_ses)
//{
//    int ret_val;
//    otzc_encode *temp_encode, *enc_context;
//    otzc_shared_mem *shared_mem, *temp_shared;
//    u32 dev_file_id = (u32)private_data;
//
//    if(!temp_svc || !temp_ses)
//        return;
//
//    TDEBUG("freeing ses_id %d  ",temp_ses->session_id);
//
//    ret_val = otz_smc_call(dev_file_id, OTZ_SVC_GLOBAL,
//        OTZ_GLOBAL_CMD_ID_CLOSE_SESSION, 0, 0,
//        &temp_svc->service_id,
//        sizeof(temp_svc->service_id),&temp_ses->session_id,
//        sizeof(temp_ses->session_id), NULL, NULL, NULL, NULL);
//
//    list_del(&temp_ses->head);
//
//    if (!list_empty(&temp_ses->encode_list)) {
//        list_for_each_entry_safe(enc_context, temp_encode,
//                    &temp_ses->encode_list, head) {
//            list_del(&enc_context->head);
//            kfree(enc_context);
//        }
//    }
//
//    if (!list_empty(&temp_ses->shared_mem_list)) {
//        list_for_each_entry_safe(shared_mem, temp_shared,
//                    &temp_ses->shared_mem_list, s_head) {
//            list_del(&shared_mem->s_head);
//
//            if(shared_mem->k_addr)
//                free_pages((u32)shared_mem->k_addr,
//                    get_order(ROUND_UP(shared_mem->len, SZ_4K)));
//
//            kfree(shared_mem);
//        }
//    }
//
//    kfree(temp_ses);
//}
//
/**
 * @brief Initialize a service
 *
 * @param dev_file Character device file
 * @param service_id ID of the service
 *
 * @return
 */
static int tee_client_service_init(teec_dev_file_t * dev_file, int service_id)
{
    int ret_code = 0;
    teec_service_t* svc_new;
    teec_service_t* temp_pos;

    svc_new = (teec_service_t*)kmalloc(sizeof(teec_service_t), GFP_KERNEL);
    if(!svc_new){
        TERR("kmalloc failed  ");
        ret_code = -ENOMEM;
        goto clean_prev_malloc;
    }

    svc_new->service_id = service_id;
    dev_file->service_cnt++;
    INIT_LIST_HEAD(&svc_new->sessions_list);
    list_add(&svc_new->head, &dev_file->services_list);
    goto return_func;

clean_prev_malloc:
    if (!list_empty(&dev_file->services_list)) {
        list_for_each_entry_safe(svc_new, temp_pos,
                        &dev_file->services_list, head) {
            list_del(&svc_new->head);
            kfree(svc_new);
        }
    }

return_func:
    return ret_code;
}
//
//
///**
// * @brief
// *
// * @return
// */
//static int otz_client_service_exit(void* private_data)
//{
//    otzc_shared_mem* temp_shared_mem;
//    otzc_shared_mem  *temp_pos;
//    otzc_dev_file *tem_dev_file, *tem_dev_file_pos;
//    otzc_session *temp_ses, *temp_ses_pos;
//    otzc_service* tmp_svc = NULL, *tmp_pos;
//    u32 dev_file_id;
//
//#if 0
//    list_for_each_entry_safe(temp_shared_mem, temp_pos,
//                &otzc_shared_mem_head.shared_mem_list , head) {
//        list_del(&temp_shared_mem->head);
//
//        if(temp_shared_mem->k_addr)
//            free_pages((u32)temp_shared_mem->k_addr,
//                get_order(ROUND_UP(temp_shared_mem->len, SZ_4K)));
//
//        if(temp_shared_mem)
//            kfree(temp_shared_mem);
//    }
//#endif
//
//    dev_file_id = (u32)(private_data);
//    list_for_each_entry_safe(tem_dev_file, tem_dev_file_pos,
//                &otzc_dev_file_head.dev_file_list, head) {
//        if(tem_dev_file->dev_file_id == dev_file_id){
//
//			list_for_each_entry_safe(temp_shared_mem, temp_pos,
//						&tem_dev_file->dev_shared_mem_head.shared_mem_list, head){
//				list_del(&temp_shared_mem->head);
//
//				if(temp_shared_mem->k_addr)
//					free_pages((u32)temp_shared_mem->k_addr,
//						get_order(ROUND_UP(temp_shared_mem->len, SZ_4K)));
//
//				if(temp_shared_mem)
//					kfree(temp_shared_mem);
//			}
//            if (!list_empty(&tem_dev_file->services_list)) {
//
//                list_for_each_entry_safe(tmp_svc, tmp_pos,
//                                        &tem_dev_file->services_list, head) {
//
//                    list_for_each_entry_safe(temp_ses, temp_ses_pos,
//                                    &tmp_svc->sessions_list, head) {
//                        otz_client_close_session_for_service(private_data,
//                                                            tmp_svc, temp_ses);
//                    }
//                    list_del(&tmp_svc->head);
//                    kfree(tmp_svc);
//                }
//            }
//
//            list_del(&tem_dev_file->head);
//            kfree(tem_dev_file);
//            break;
//        }
//    }
//
//    return 0;
//}
//
//
//
/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
static int tee_client_session_open(void* private_data, void* argp)
{
    teec_service_t* svc;
    teec_dev_file_t *temp_dev_file;
    teec_session_t* ses_new;
    service_session_id_t ses_open;
    int svc_found = 0;
    int ret_val = 0, ret_resp_len;
    u32 dev_file_id = (u32)private_data;

    TDEBUG("inside session open");

    if(copy_from_user(&ses_open, argp, sizeof(ses_open))){
        TERR("copy from user failed");
        ret_val =  -EFAULT;
        goto return_func;
    }

    list_for_each_entry(temp_dev_file, &teec_dev_file_head.dev_file_list,
                                                                    head) {
        if(temp_dev_file->dev_file_id == dev_file_id){

            list_for_each_entry(svc, &temp_dev_file->services_list, head){
                if( svc->service_id == ses_open.service_id){
                    svc_found = 1;
                    break;
                }
            }
            break;
        }
    }

    if(!svc_found) {
        ret_val =  -EINVAL;
        goto return_func;
    }

    ses_new = (teec_session_t*)kmalloc(sizeof(teec_session_t), GFP_KERNEL);
    if(!ses_new) {
        TERR("kmalloc failed ");
        ret_val =  -ENOMEM;
        goto return_func;
    }

    TDEBUG("service id 0x%x ", ses_open.service_id);

    ret_val = teec_smc_call(dev_file_id, TEE_SVC_GLOBAL,
            TEE_SVC_GLOBAL_CMD_ID_OPEN_SESSION, 0, 0,
        &ses_open.service_id, sizeof(ses_open.service_id), &ses_new->session_id,
        sizeof(ses_new->session_id), NULL, &ret_resp_len, NULL, NULL);

    if(ret_val != SMC_SUCCESS) {
        goto clean_session;
    }

    if(ses_new->session_id == -1) {
        TERR("invalid session id ");
        ret_val =  -EINVAL;
        goto clean_session;
    }

    TDEBUG("session id 0x%x for service id 0x%x ", ses_new->session_id,
            ses_open.service_id);

    ses_open.session_id = ses_new->session_id;

    INIT_LIST_HEAD(&ses_new->encode_list);
    INIT_LIST_HEAD(&ses_new->shared_mem_list);
    list_add_tail(&ses_new->head, &svc->sessions_list);

    if(copy_to_user(argp, &ses_open, sizeof(ses_open))) {
        TERR("copy from user failed ");
        ret_val =  -EFAULT;
        goto clean_hdr_buf;
    }

 /*   TDEBUG("session created from service  "); */
    goto return_func;

clean_hdr_buf:
    list_del(&ses_new->head);

clean_session:
    kfree(ses_new);

return_func:

    return ret_val;
}
//
///**
// * @brief
// *
// * @param argp
// *
// * @return
// */
//static int otz_client_session_close(void* private_data, void* argp)
//{
//    otzc_dev_file *temp_dev_file;
//    otzc_service *temp_svc;
//    otzc_session *temp_ses;
//    int ret_val = 0;
//    u32 dev_file_id = (u32)private_data;
//
//    struct ser_ses_id ses_close;
//
//    TDEBUG("inside session close ");
//
//    if(copy_from_user(&ses_close, argp, sizeof(ses_close))) {
//        TERR("copy from user failed  ");
//        ret_val = -EFAULT;
//        goto return_func;
//    }
//
//    list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
//                                                                    head) {
//        if(temp_dev_file->dev_file_id == dev_file_id){
//
//            list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
//                if( temp_svc->service_id == ses_close.service_id) {
//
//                    list_for_each_entry(temp_ses,
//                                        &temp_svc->sessions_list, head) {
//                        if(temp_ses->session_id == ses_close.session_id) {
//                            otz_client_close_session_for_service(private_data,
//                                                            temp_svc, temp_ses);
//                            break;
//                        }
//                    }
//                    break;
//                }
//            }
//            break;
//        }
//    }
//
//    TDEBUG("return from close ");
//
//return_func:
//    return ret_val;
//}
//
//
///**
// * @brief
// *
// * @return
// */
//static int otz_client_register_service(void)
//{
///* Query secure and find out */
//    return 0;
//}
//
///**
// * @brief
// *
// * @return
// */
//static int otz_client_unregister_service(void)
//{
///*query secure and do*/
//    return 0;
//}
//
///**
// * @brief
// *
// * @param filp
// * @param vma
// *
// * @return
// */
static int tee_driver_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret = 0;
//    otzc_shared_mem *mem_new;
//    u32*  alloc_addr;
//    long length = vma->vm_end - vma->vm_start;
//
//    TDEBUG("Inside otz_client mmap ");
//
//    alloc_addr =  (void*) __get_free_pages(GFP_KERNEL,
//                        get_order(ROUND_UP(length, SZ_4K)));
//    if(!alloc_addr) {
//        TERR("get free pages failed  ");
//        ret = -ENOMEM;
//        goto return_func;
//    }
//
//    TDEBUG("mmap k_addr %p  ",alloc_addr);
//
//    if (remap_pfn_range(vma,
//                vma->vm_start,
//                ((virt_to_phys(alloc_addr)) >> PAGE_SHIFT),
//                length,
//                vma->vm_page_prot)) {
//        ret = -EAGAIN;
//        goto return_func;
//    }
//
//    mem_new = kmalloc(sizeof(otzc_shared_mem), GFP_KERNEL);
//    if(!mem_new) {
//        TERR("kmalloc failed ");
//        ret = -ENOMEM;
//        goto return_func;
//    }
//
//    mem_new->k_addr = alloc_addr;
//    mem_new->len = length;
//    mem_new->u_addr = (void*)vma->vm_start;
//    mem_new->index = mem_new->u_addr;
//
//	otzc_dev_file *temp_dev_file;
//    list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
//                                                                    head) {
//        if(temp_dev_file->dev_file_id == (u32)filp->private_data){
//			break;
//		}
//	}
//    temp_dev_file->dev_shared_mem_head.shared_mem_cnt++;
//    list_add_tail( &mem_new->head ,&temp_dev_file->dev_shared_mem_head.shared_mem_list);
//
//return_func:
    return ret;
}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
static int tee_client_send_cmd(void* private_data, void* argp)
{
    int ret = 0;
    int ret_resp_len = 0;
    tee_client_encode_cmd_t enc;
    int dev_file_id;

    teec_dev_file_t *temp_dev_file;
    teec_service_t *temp_svc;
    teec_session_t *temp_ses;
    teec_encode_t *enc_temp;

    int enc_found = 0;
    dev_file_id = (u32)private_data;

    TDEBUG("inside send cmd  ");

    if(copy_from_user(&enc, argp, sizeof(enc))) {
        TERR("copy from user failed  ");
        ret = -EFAULT;
        goto return_func;
    }

    TDEBUG("enc id %d ",enc.encode_id);
    TDEBUG("dev file id %d ",dev_file_id);
    TDEBUG("ser id %d ",enc.service_id);
    TDEBUG("ses id %d ",enc.session_id);

    list_for_each_entry(temp_dev_file, &teec_dev_file_head.dev_file_list,
                                                                    head) {
        if(temp_dev_file->dev_file_id == dev_file_id){

            list_for_each_entry(temp_svc, &temp_dev_file->services_list, head){
                if(temp_svc->service_id == enc.service_id) {
                    TDEBUG("send cmd ser id %d  ",temp_svc->service_id);

                    list_for_each_entry(temp_ses, &temp_svc->sessions_list,
                            head) {
                        if(temp_ses->session_id == enc.session_id) {
                            TDEBUG("send cmd ses id %d  ",
                                    temp_ses->session_id);

                            if(enc.encode_id != -1) {
                                list_for_each_entry(enc_temp,
                                    &temp_ses->encode_list, head) {
                                    if(enc_temp->encode_id == enc.encode_id) {
                                        TDEBUG("send cmd enc id 0x%x ",
                                                        enc_temp->encode_id);
                                        enc_found = 1;
                                        break;
                                    }
                                }
                            }
                            else {
                                    ret = tee_client_prepare_encode(
                                            private_data,
                                            &enc, &enc_temp, &temp_ses);
                                    if(!ret) {
                                        enc_found = 1;
                                    }
                                    break;
                            }
                        }
                        break;
                    }
                    break;
                }
            }
            break;
        }
    }

    if(!enc_found){
        ret = -EINVAL;
        goto return_func;
    }


    ret = teec_smc_call(dev_file_id, enc.service_id, enc.cmd_id, enc.session_id,
        enc.encode_id,
        enc_temp->ker_req_data_addr, enc_temp->enc_req_offset,
        enc_temp->ker_res_data_addr, enc_temp->enc_res_offset,
        enc_temp->meta, &ret_resp_len, &enc_temp->wait_data , &send_cmd_lock);

    if(ret != SMC_SUCCESS) {
         TERR("send cmd secure call failed  ");
         goto return_func;
    }

    TDEBUG("smc_success ");

    if(copy_to_user(argp, &enc, sizeof(enc))) {
        TERR("copy to user failed  ");
        ret = -EFAULT;
        goto return_func;
    }

return_func:
   return ret;

}
//
///**
// * @brief
// *
// * @param argp
// *
// * @return
// */
//static int otz_client_operation_release(void* private_data, void *argp)
//{
//    struct otz_client_encode_cmd enc;
//    otzc_encode *enc_context;
//    otzc_dev_file *temp_dev_file;
//    otzc_service *temp_svc;
//    otzc_session *temp_ses;
//    int  session_found = 0, enc_found = 0;
//    int ret =0;
//    u32 dev_file_id = (u32)private_data;
//
//    if(copy_from_user(&enc, argp, sizeof(enc))) {
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//    list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
//                                                                    head) {
//        if(temp_dev_file->dev_file_id == dev_file_id){
//
//            list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
//                if( temp_svc->service_id == enc.service_id) {
//                    list_for_each_entry(temp_ses, &temp_svc->sessions_list, head) {
//                        if(temp_ses->session_id == enc.session_id) {
//                            session_found = 1;
//                            break;
//                        }
//                    }
//                    break;
//                }
//            }
//            break;
//        }
//    }
//
//    if(!session_found) {
//        ret = -EINVAL;
//        goto return_func;
//    }
//
//    if(enc.encode_id != -1) {
//        list_for_each_entry(enc_context,&temp_ses->encode_list, head) {
//            if(enc_context->encode_id == enc.encode_id) {
//                enc_found = 1;
//                break;
//            }
//        }
//    }
//
//    if(enc_found && enc_context) {
//       if(enc_context->ker_req_data_addr)
//         kfree(enc_context->ker_req_data_addr);
//
//        if(enc_context->ker_res_data_addr)
//            kfree(enc_context->ker_res_data_addr);
//
//        list_del(&enc_context->head);
//
//        kfree(enc_context->meta);
//        kfree(enc_context);
//    }
//return_func:
//    return ret;
//}
//
/**
 * @brief
 *
 * @param enc
 * @param penc_context
 * @param psession
 *
 * @return
 */
static int tee_client_prepare_encode( void* private_data,
                                      tee_client_encode_cmd_t *enc,
                                      teec_encode_t **penc_context,
                                      teec_session_t **psession)
{
    teec_dev_file_t *temp_dev_file;
    teec_service_t *temp_svc;
    teec_session_t *temp_ses;
    teec_encode_t *enc_context;
    int  session_found = 0, enc_found = 0;
    int ret = 0;
    u32 dev_file_id = (u32)private_data;

    list_for_each_entry(temp_dev_file, &teec_dev_file_head.dev_file_list,
                                                                    head) {
        if(temp_dev_file->dev_file_id == dev_file_id){


            list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
                if( temp_svc->service_id == enc->service_id) {
                    list_for_each_entry(temp_ses, &temp_svc->sessions_list,
                                                                        head) {
                        if(temp_ses->session_id == enc->session_id) {
                            TDEBUG("enc cmd ses id %d  ",temp_ses->session_id);
                            session_found = 1;
                            break;
                        }
                    }
                    break;
                }
            }
            break;
        }
    }

    if(!session_found) {
        TERR("session not found ");
        ret = -EINVAL;
        goto return_func;
    }

    if(enc->encode_id != -1) {
        list_for_each_entry(enc_context,&temp_ses->encode_list, head) {
            if(enc_context->encode_id == enc->encode_id) {
                enc_found = 1;
                break;
            }
        }
    }

    if(!enc_found) {
        enc_context = kmalloc(sizeof(teec_encode_t), GFP_KERNEL);
        if(!enc_context) {
            TERR("kmalloc failed  ");
            ret = -ENOMEM;
            goto return_func;
        }
        enc_context->meta = kmalloc(sizeof(teec_encode_meta_t ) *
            (TEE_MAX_RES_PARAMS + TEE_MAX_REQ_PARAMS),
            GFP_KERNEL);
        if(!enc_context->meta) {
            TERR("kmalloc failed  ");
            kfree(enc_context);
            ret = -ENOMEM;
            goto return_func;
        }
        enc_context->encode_id = (int)enc_context;
        enc->encode_id = enc_context->encode_id;
        enc_context->ker_req_data_addr = NULL;
        enc_context->ker_res_data_addr = NULL;
        enc_context->enc_req_offset = 0;
        enc_context->enc_res_offset = 0;
        enc_context->enc_req_pos = 0;
        enc_context->enc_res_pos = TEE_MAX_REQ_PARAMS;
        enc_context->dec_res_pos = TEE_MAX_REQ_PARAMS;
        enc_context->dec_offset = 0;

        list_add_tail(&enc_context->head, &temp_ses->encode_list);
    }

    *penc_context = enc_context;
    *psession = temp_ses;

return_func:
    return ret;
}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
static int tee_client_encode_uint32(void* private_data, void* argp)
{
    tee_client_encode_cmd_t enc;
    int ret = 0;
    teec_session_t *session;
    teec_encode_t *enc_context;


    if(copy_from_user(&enc, argp, sizeof(enc))) {
        TERR("copy from user failed  ");
        ret = -EFAULT;
        goto return_func;
    }

    ret = tee_client_prepare_encode(private_data, &enc, &enc_context, &session);

    if(ret){
        goto return_func;
    }

    if(enc.param_type == TEEC_PARAM_IN) {
        if(!enc_context->ker_req_data_addr) {
           enc_context->ker_req_data_addr =
                kmalloc(TEE_1K_SIZE, GFP_KERNEL);
            if(!enc_context->ker_req_data_addr) {
                TERR("kmalloc failed  ");
                ret =  -ENOMEM;
                goto ret_encode_u32;
            }
        }
        if( (enc_context->enc_req_offset + sizeof(u32) <= TEE_1K_SIZE) &&
            (enc_context->enc_req_pos < TEE_MAX_REQ_PARAMS)) {
            *(u32*)(enc_context->ker_req_data_addr +
                enc_context->enc_req_offset) = *((u32*)enc.data);
            enc_context->enc_req_offset += sizeof(u32);
            enc_context->meta[enc_context->enc_req_pos].type = TEE_ENC_UINT32;
            enc_context->meta[enc_context->enc_req_pos].len = sizeof(u32);
            enc_context->enc_req_pos++;
        }
        else {
            ret =  -ENOMEM;/* Check this */
            goto ret_encode_u32;
        }
    }
    else if(enc.param_type == TEEC_PARAM_OUT) {
        if(!enc_context->ker_res_data_addr) {
            enc_context->ker_res_data_addr =
                kmalloc(TEE_1K_SIZE, GFP_KERNEL);
            if(!enc_context->ker_res_data_addr) {
                TERR("kmalloc failed  ");
                ret = -ENOMEM;
                goto ret_encode_u32;
            }
        }
        if( (enc_context->enc_res_offset + sizeof(u32) <= TEE_1K_SIZE) &&
            (enc_context->enc_res_pos <
            (TEE_MAX_RES_PARAMS + TEE_MAX_REQ_PARAMS ))) {

            if(enc.data != NULL) {
                enc_context->meta[enc_context->enc_res_pos].usr_addr
                    = (u32)enc.data;
            }
            else {
                enc_context->meta[enc_context->enc_res_pos].usr_addr = 0;
            }
            enc_context->enc_res_offset += sizeof(u32);
            enc_context->meta[enc_context->enc_res_pos].type = TEE_ENC_UINT32;
            enc_context->meta[enc_context->enc_res_pos].len = sizeof(u32);
            enc_context->enc_res_pos++;
        }
        else {
            ret =  -ENOMEM; /* check this */
            goto ret_encode_u32;
        }
    }


ret_encode_u32:
    if(copy_to_user(argp, &enc, sizeof(enc))){
        TERR("copy from user failed  ");
        return -EFAULT;
    }

return_func:
    return ret;
}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
//static int otz_client_encode_array(void* private_data, void* argp)
//{
//    struct otz_client_encode_cmd enc;
//    int ret = 0;
//    otzc_encode *enc_context;
//    otzc_session *session;
//
//    if(copy_from_user(&enc, argp, sizeof(enc))) {
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//    ret = otz_client_prepare_encode(private_data, &enc, &enc_context, &session);
//
//    if(ret){
//        goto return_func;
//    }
//    TDEBUG("enc_id 0x%x ",enc_context->encode_id);
//
//    if(enc.param_type == OTZC_PARAM_IN) {
//        if(!enc_context->ker_req_data_addr) {
//            TDEBUG("allocate req data ");
//            enc_context->ker_req_data_addr = kmalloc(OTZ_1K_SIZE, GFP_KERNEL);
//            if(!enc_context->ker_req_data_addr) {
//                TERR("kmalloc failed  ");
//                ret = -ENOMEM;
//                goto ret_encode_array;
//             }
//        }
//        TDEBUG("append encode data ");
//
//        if((enc_context->enc_req_offset + enc.len <= OTZ_1K_SIZE) &&
//              (enc_context->enc_req_pos < OTZ_MAX_REQ_PARAMS)) {
//            if(copy_from_user(
//                enc_context->ker_req_data_addr + enc_context->enc_req_offset,
//                enc.data ,
//                enc.len)) {
//                TERR("copy from user failed  ");
//                    ret = -EFAULT;
//                    goto ret_encode_array;
//            }
//            enc_context->enc_req_offset += enc.len;
//
//            enc_context->meta[enc_context->enc_req_pos].type = OTZ_ENC_ARRAY;
//            enc_context->meta[enc_context->enc_req_pos].len = enc.len;
//            enc_context->enc_req_pos++;
//        }
//        else {
//            ret = -ENOMEM; /* Check this */
//            goto ret_encode_array;
//        }
//    }
//    else if(enc.param_type == OTZC_PARAM_OUT) {
//        if(!enc_context->ker_res_data_addr) {
//            enc_context->ker_res_data_addr = kmalloc(OTZ_1K_SIZE, GFP_KERNEL);
//            if(!enc_context->ker_res_data_addr) {
//                TERR("kmalloc failed  ");
//                ret = -ENOMEM;
//                goto ret_encode_array;
//            }
//        }
//        if((enc_context->enc_res_offset + enc.len <= OTZ_1K_SIZE) &&
//            (enc_context->enc_res_pos <
//            (OTZ_MAX_RES_PARAMS + OTZ_MAX_REQ_PARAMS ))) {
//            if(enc.data != NULL) {
//                enc_context->meta[enc_context->enc_res_pos].usr_addr
//                    = (u32)enc.data;
//            }
//            else {
//                enc_context->meta[enc_context->enc_res_pos].usr_addr = 0;
//            }
//            enc_context->enc_res_offset += enc.len;
//            enc_context->meta[enc_context->enc_res_pos].type = OTZ_ENC_ARRAY;
//            enc_context->meta[enc_context->enc_res_pos].len = enc.len;
//
//            enc_context->enc_res_pos++;
//        }
//        else {
//            ret = -ENOMEM;/* Check this */
//            goto ret_encode_array;
//        }
//    }
//
//ret_encode_array:
//    if(copy_to_user(argp, &enc, sizeof(enc))){
//        TERR("copy from user failed  ");
//        return -EFAULT;
//    }
//
//return_func:
//    return ret;
//}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
//static int otz_client_encode_mem_ref(void* private_data, void* argp)
//{
//    struct otz_client_encode_cmd enc;
//    int ret = 0, shared_mem_found = 0;
//    otzc_encode *enc_context;
//    otzc_session *session;
//    otzc_shared_mem* temp_shared_mem;
//
//    if(copy_from_user(&enc, argp, sizeof(enc))) {
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//    ret = otz_client_prepare_encode(private_data, &enc, &enc_context, &session);
//
//    if(ret){
//        goto return_func;
//    }
//    TDEBUG("enc_id 0x%x ",enc_context->encode_id);
//    list_for_each_entry(temp_shared_mem, &session->shared_mem_list,s_head){
//        if(temp_shared_mem->index == (u32*)enc.data){
//            shared_mem_found = 1;
//            break;
//        }
//    }
//
//    if(!shared_mem_found) {
//		otzc_dev_file *temp_dev_file;
//		list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
//																		head) {
//			if(temp_dev_file->dev_file_id == (u32)private_data){
//				break;
//			}
//		}
//        list_for_each_entry(temp_shared_mem,
//                    &temp_dev_file->dev_shared_mem_head.shared_mem_list ,head) {
//			TDEBUG("dev id : %d shrd_mem_index : 0x%x ",
//					temp_dev_file->dev_file_id, temp_shared_mem->index);
//            if(temp_shared_mem->index == (u32*)enc.data){
//                shared_mem_found = 1;
//                break;
//            }
//        }
//    }
//
//    if(!shared_mem_found) {
//
//        TERR("shared memory not registered for \
//this session 0x%x ", session->session_id);
//        ret = -EINVAL;
//        goto return_func;
//    }
//
//    if(enc.param_type == OTZC_PARAM_IN) {
//        if(!enc_context->ker_req_data_addr) {
//            enc_context->ker_req_data_addr = kmalloc(OTZ_1K_SIZE, GFP_KERNEL);
//            if(!enc_context->ker_req_data_addr) {
//                TERR("kmalloc failed  ");
//                ret = -ENOMEM;
//                goto ret_encode_array;
//             }
//        }
//
//        if((enc_context->enc_req_offset + sizeof(u32) <=
//              OTZ_1K_SIZE) &&
//              (enc_context->enc_req_pos < OTZ_MAX_REQ_PARAMS)) {
//            *((u32*)enc_context->ker_req_data_addr +
//                enc_context->enc_req_offset)
//                     = virt_to_phys(temp_shared_mem->k_addr+enc.offset);
//            enc_context->enc_req_offset += sizeof(u32);
//            enc_context->meta[enc_context->enc_req_pos].usr_addr
//                              = (u32)(temp_shared_mem->u_addr + enc.offset);
//            enc_context->meta[enc_context->enc_req_pos].type = OTZ_MEM_REF;
//            enc_context->meta[enc_context->enc_req_pos].len = enc.len;
//
//            enc_context->enc_req_pos++;
//        }
//        else {
//            ret = -ENOMEM; /* Check this */
//            goto ret_encode_array;
//        }
//    }
//    else if(enc.param_type == OTZC_PARAM_OUT) {
//        if(!enc_context->ker_res_data_addr) {
//            enc_context->ker_res_data_addr = kmalloc(OTZ_1K_SIZE, GFP_KERNEL);
//            if(!enc_context->ker_res_data_addr) {
//                TERR("kmalloc failed  ");
//                ret = -ENOMEM;
//                goto ret_encode_array;
//            }
//        }
//        if((enc_context->enc_res_offset + sizeof(u32)
//            <= OTZ_1K_SIZE) &&
//            (enc_context->enc_res_pos <
//            (OTZ_MAX_RES_PARAMS + OTZ_MAX_REQ_PARAMS ))) {
//            *((u32*)enc_context->ker_res_data_addr +
//                    enc_context->enc_res_offset)
//                        = virt_to_phys(temp_shared_mem->k_addr + enc.offset);
//            enc_context->enc_res_offset += sizeof(u32);
//            enc_context->meta[enc_context->enc_res_pos].usr_addr
//                        = (u32)(temp_shared_mem->u_addr + enc.offset);
//            enc_context->meta[enc_context->enc_res_pos].type
//                                                =  OTZ_MEM_REF;
//            enc_context->meta[enc_context->enc_res_pos].len = enc.len;
//            enc_context->enc_res_pos++;
//        }
//        else {
//            ret = -ENOMEM; /*Check this */
//            goto ret_encode_array;
//        }
//    }
//
//ret_encode_array:
//    if(copy_to_user(argp, &enc, sizeof(enc))){
//        TERR("copy from user failed  ");
//        return -EFAULT;
//    }
//
//return_func:
//    return ret;
//}


/**
 * @brief
 *
 * @param dec
 * @param pdec_context
 *
 * @return
 */
//static int otz_client_prepare_decode(void* private_data,
//                                     struct otz_client_encode_cmd *dec,
//                                     otzc_encode **pdec_context)
//{
//    otzc_dev_file *temp_dev_file;
//    otzc_service *temp_svc;
//    otzc_session *temp_ses;
//    otzc_encode *dec_context;
//    int  session_found = 0, enc_found = 0;
//    int ret = 0;
//    u32 dev_file_id = (u32)private_data;
//
//    list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
//                                                                    head) {
//        if(temp_dev_file->dev_file_id == dev_file_id){
//
//            list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
//                if( temp_svc->service_id == dec->service_id) {
//                    list_for_each_entry(temp_ses, &temp_svc->sessions_list,
//                                                                    head) {
//                        if(temp_ses->session_id == dec->session_id) {
//                            TDEBUG("enc cmd ses id %d  ",temp_ses->session_id);
//                            session_found = 1;
//                            break;
//                        }
//                    }
//                    break;
//                }
//            }
//            break;
//        }
//    }
//
//    if(!session_found) {
//        TERR("session not found ");
//        ret = -EINVAL;
//        goto return_func;
//    }
//
//    if(dec->encode_id != -1) {
//        list_for_each_entry(dec_context,&temp_ses->encode_list, head) {
//            if(dec_context->encode_id == dec->encode_id){
//                enc_found = 1;
//                break;
//            }
//        }
//    }
//
//    if(!enc_found) {
//        ret =  -EINVAL;
//        goto return_func;
//    }
//
//    *pdec_context = dec_context;
//return_func:
//    return ret;
//}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
//static int otz_client_decode_uint32(void* private_data, void* argp)
//{
//    struct otz_client_encode_cmd dec;
//    int ret = 0;
//    otzc_encode *dec_context;
//
//
//    if(copy_from_user(&dec, argp, sizeof(dec))) {
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//    ret = otz_client_prepare_decode(private_data, &dec, &dec_context);
//
//    if(ret) {
//        goto return_func;
//    }
//
//    if((dec_context->dec_res_pos <= dec_context->enc_res_pos) &&
//      (dec_context->meta[dec_context->dec_res_pos].type
//                                                == OTZ_ENC_UINT32)){
//
//        if(dec_context->meta[dec_context->dec_res_pos].usr_addr) {
//            dec.data =
//                (void*)dec_context->meta[dec_context->dec_res_pos].usr_addr;
//         }
//
//        *(u32*)dec.data =  *((u32*)(dec_context->ker_res_data_addr
//                                     + dec_context->dec_offset));
//        dec_context->dec_offset += sizeof(u32);
//        dec_context->dec_res_pos++;
//    }
//    if(copy_to_user(argp, &dec, sizeof(dec))){
//        TERR("copy to user failed  ");
//        return -EFAULT;
//    }
//
//return_func:
//    return ret;
//}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
//static int otz_client_decode_array_space(void* private_data, void* argp)
//{
//    struct otz_client_encode_cmd dec;
//    int ret = 0;
//    otzc_encode *dec_context;
//
//
//    if(copy_from_user(&dec, argp, sizeof(dec))) {
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//    ret = otz_client_prepare_decode(private_data, &dec, &dec_context);
//
//    if(ret){
//        goto return_func;
//    }
//
//    if((dec_context->dec_res_pos <= dec_context->enc_res_pos) &&
//            (dec_context->meta[dec_context->dec_res_pos].type
//                    == OTZ_ENC_ARRAY)) {
//        if (dec_context->meta[dec_context->dec_res_pos].len >=
//                    dec_context->meta[dec_context->dec_res_pos].ret_len) {
//            if(dec_context->meta[dec_context->dec_res_pos].usr_addr) {
//                dec.data =
//                    (void*)dec_context->meta[dec_context->dec_res_pos].usr_addr;
//            }
//            if(copy_to_user(dec.data,
//            dec_context->ker_res_data_addr + dec_context->dec_offset,
//            dec_context->meta[dec_context->dec_res_pos].ret_len)){
//                TERR("copy from user failed while copying array ");
//                ret = -EFAULT;
//                goto return_func;
//            }
//        }
//        else {
//            TERR("buffer length is small. Length required %d \
//and supplied length %d ",
//            dec_context->meta[dec_context->dec_res_pos].ret_len,
//            dec_context->meta[dec_context->dec_res_pos].len);
//            ret = -EFAULT; /* check this */
//            goto return_func;
//        }
//
//        dec.len = dec_context->meta[dec_context->dec_res_pos].ret_len;
//        dec_context->dec_offset +=
//                            dec_context->meta[dec_context->dec_res_pos].len;
//        dec_context->dec_res_pos++;
//    }
//    else if((dec_context->dec_res_pos <= dec_context->enc_res_pos) &&
//            (dec_context->meta[dec_context->dec_res_pos].type
//                    == OTZ_MEM_REF)) {
//        if (dec_context->meta[dec_context->dec_res_pos].len >=
//                    dec_context->meta[dec_context->dec_res_pos].ret_len) {
//            dec.data =
//                (void*)dec_context->meta[dec_context->dec_res_pos].usr_addr;
//        }
//        else {
//            TERR("buffer length is small. Length required %d \
//and supplied length %d ",
//            dec_context->meta[dec_context->dec_res_pos].ret_len,
//            dec_context->meta[dec_context->dec_res_pos].len);
//            ret = -EFAULT;/* Check this */
//            goto return_func;
//        }
//
//        dec.len = dec_context->meta[dec_context->dec_res_pos].ret_len;
//        dec_context->dec_offset += sizeof(u32);
//        dec_context->dec_res_pos++;
//    }
//
//    else {
//        TERR("invalid data type or decoder at wrong position ");
//        ret = -EINVAL;
//        goto return_func;
//    }
//
//     if(copy_to_user(argp, &dec, sizeof(dec))){
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//       goto return_func;
//    }
//
//return_func:
//    return ret;
//}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
//static int otz_client_get_decode_type(void* private_data, void* argp)
//{
//    struct otz_client_encode_cmd dec;
//    int ret = 0;
//    otzc_encode *dec_context;
//
//
//    if(copy_from_user(&dec, argp, sizeof(dec))){
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//    ret = otz_client_prepare_decode(private_data, &dec, &dec_context);
//
//    if(ret){
//        goto return_func;
//    }
//
//    TDEBUG("decoder pos 0x%x and encoder pos 0x%x ",
//        dec_context->dec_res_pos, dec_context->enc_res_pos);
//
//    if(dec_context->dec_res_pos <= dec_context->enc_res_pos)
//        dec.data = (void*)dec_context->meta[dec_context->dec_res_pos].type;
//    else {
//        ret = -EINVAL; /* check this */
//        goto return_func;
//    }
//
//   if(copy_to_user(argp, &dec, sizeof(dec))){
//        TERR("copy to user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//return_func:
//    return ret;
//}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
//static int otz_client_shared_mem_alloc(void* private_data, void* argp)
//{
//    otzc_shared_mem* temp_shared_mem;
//    struct otz_session_shared_mem_info mem_info;
//
//    otzc_dev_file *temp_dev_file;
//    otzc_service *temp_svc;
//    otzc_session *temp_ses;
//
//    int  session_found = 0;
//    int ret = 0;
//    u32 dev_file_id = (u32)private_data;
//
//    if(copy_from_user(&mem_info, argp, sizeof(mem_info))){
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//    TDEBUG("service id 0x%x session id 0x%x user mem addr 0x%x  ",
//            mem_info.service_id,
//            mem_info.session_id,
//            mem_info.user_mem_addr);
//    list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
//                                                                    head) {
//        if(temp_dev_file->dev_file_id == dev_file_id){
//
//            list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
//                if( temp_svc->service_id == mem_info.service_id) {
//                    list_for_each_entry(temp_ses, &temp_svc->sessions_list, head) {
//                        if(temp_ses->session_id == mem_info.session_id) {
//                            session_found = 1;
//                            break;
//                        }
//                    }
//                    break;
//                }
//            }
//            break;
//        }
//    }
//
//    if(!session_found) {
//        TERR("session not found ");
//        ret = -EINVAL;
//        goto return_func;
//    }
//
//    list_for_each_entry(temp_shared_mem, &temp_dev_file->dev_shared_mem_head.shared_mem_list ,
//                                                                       head){
//        if(temp_shared_mem->index == (u32*)mem_info.user_mem_addr){
//            list_del(&temp_shared_mem->head);
//            temp_dev_file->dev_shared_mem_head.shared_mem_cnt--;
//            list_add_tail( &temp_shared_mem->s_head ,
//                                    &temp_ses->shared_mem_list);
//            break;
//        }
//    }
//return_func:
//    return ret;
//}

/**
 * @brief
 *
 * @param argp
 *
 * @return
 */
//static int otz_client_shared_mem_free(void* private_data, void* argp)
//{
//    otzc_shared_mem* temp_shared_mem;
//    struct otz_session_shared_mem_info mem_info;
//
//    otzc_dev_file *temp_dev_file;
//    otzc_service *temp_svc;
//    otzc_session *temp_ses;
//
//    int  session_found = 0;
//    int ret = 0;
//    u32 dev_file_id = (u32)private_data;
//
//    if(copy_from_user(&mem_info, argp, sizeof(mem_info))){
//        TERR("copy from user failed  ");
//        ret = -EFAULT;
//        goto return_func;
//    }
//
//    TDEBUG("service id 0x%x session id 0x%x user mem addr 0x%x  ",
//            mem_info.service_id,
//            mem_info.session_id,
//            mem_info.user_mem_addr);
//    list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
//                                                                    head) {
//        if(temp_dev_file->dev_file_id == dev_file_id){
//
//            list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
//                if( temp_svc->service_id == mem_info.service_id) {
//                    list_for_each_entry(temp_ses, &temp_svc->sessions_list, head) {
//                        if(temp_ses->session_id == mem_info.session_id) {
//                            session_found = 1;
//                            break;
//                        }
//                    }
//                    break;
//                }
//            }
//            break;
//        }
//    }
//
//    if(!session_found) {
//        TERR("session not found ");
//        ret = -EINVAL;
//        goto return_func;
//    }
//
//    list_for_each_entry(temp_shared_mem, &temp_ses->shared_mem_list,s_head){
//        if(temp_shared_mem->index == (u32*)mem_info.user_mem_addr){
//            list_del(&temp_shared_mem->s_head);
//
//            if(temp_shared_mem->k_addr)
//                free_pages((u32)temp_shared_mem->k_addr,
//                    get_order(ROUND_UP(temp_shared_mem->len, SZ_4K)));
//
//            if(temp_shared_mem)
//                kfree(temp_shared_mem);
//            break;
//        }
//    }
//return_func:
//    return ret;
//}

/**
 * @brief
 *
 * @param file
 * @param cmd
 * @param arg
 *
 * @return
 */
static long tee_driver_ioctl(struct file *file, unsigned cmd,
        unsigned long arg)
{ // TODO IOCTL
    int ret = -EINVAL;
    void *argp = (void __user *) arg;

    switch (cmd) {
    case TEE_CLIENT_IOCTL_SEND_CMD_REQ: {
        /* Only one client allowed here at a time */
        mutex_lock(&send_cmd_lock);
        ret = tee_client_send_cmd(file->private_data, argp);
        mutex_unlock(&send_cmd_lock);

        if (ret)
            TDEBUG("failed tee_client_send_cmd: %d", ret);
        break;
    }

    case TEE_CLIENT_IOCTL_ENC_UINT32: {

    	/* Only one client allowed here at a time */
        mutex_lock(&encode_cmd_lock);
        ret = tee_client_encode_uint32(file->private_data, argp);
        mutex_unlock(&encode_cmd_lock);
        if (ret)
            TDEBUG("failed tee_client_encode_cmd: %d", ret);
        break;
    }
//    case OTZ_CLIENT_IOCTL_DEC_UINT32: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&decode_cmd_lock);
//        ret = otz_client_decode_uint32(file->private_data, argp);
//        mutex_unlock(&decode_cmd_lock);
//        if (ret)
//            TDEBUG("failed otz_client_decode_cmd: %d", ret);
//        break;
//    }
//    case OTZ_CLIENT_IOCTL_ENC_ARRAY: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&encode_cmd_lock);
//        ret = otz_client_encode_array(file->private_data, argp);
//        mutex_unlock(&encode_cmd_lock);
//        if (ret)
//            TDEBUG("failed otz_client_encode_cmd: %d", ret);
//        break;
//    }
//    case OTZ_CLIENT_IOCTL_DEC_ARRAY_SPACE: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&decode_cmd_lock);
//        ret = otz_client_decode_array_space(file->private_data, argp);
//        mutex_unlock(&decode_cmd_lock);
//        if (ret)
//            TDEBUG("failed otz_client_decode_cmd: %d", ret);
//        break;
//    }
//    case OTZ_CLIENT_IOCTL_ENC_MEM_REF: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&encode_cmd_lock);
//        ret = otz_client_encode_mem_ref(file->private_data, argp);
//        mutex_unlock(&encode_cmd_lock);
//        if (ret)
//            TDEBUG("failed otz_client_encode_cmd: %d", ret);
//        break;
//    }
//    case OTZ_CLIENT_IOCTL_ENC_ARRAY_SPACE: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&encode_cmd_lock);
//        ret = otz_client_encode_mem_ref(file->private_data, argp);
//        mutex_unlock(&encode_cmd_lock);
//        if (ret)
//            TDEBUG("failed otz_client_encode_cmd: %d", ret);
//        break;
//    }
//    case OTZ_CLIENT_IOCTL_GET_DECODE_TYPE: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&decode_cmd_lock);
//        ret = otz_client_get_decode_type(file->private_data, argp);
//        mutex_unlock(&decode_cmd_lock);
//        if (ret)
//            TDEBUG("failed otz_client_decode_cmd: %d", ret);
//        break;
//    }
    case TEE_CLIENT_IOCTL_SES_OPEN_REQ: {
        /* Only one client allowed here at a time */
        mutex_lock(&ses_open_lock);
        ret = tee_client_session_open(file->private_data, argp);
        mutex_unlock(&ses_open_lock);
        if (ret)
            TDEBUG("failed tee_client_session_open: %d", ret);
        break;
    }
//    case OTZ_CLIENT_IOCTL_SES_CLOSE_REQ: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&ses_close_lock);
//        ret = otz_client_session_close(file->private_data, argp);
//        mutex_unlock(&ses_close_lock);
//        if (ret)
//            TDEBUG("failed otz_client_session_close: %d", ret);
//        break;
//    }
//    case OTZ_CLIENT_IOCTL_SHR_MEM_ALLOCATE_REQ: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&mem_alloc_lock);
//        ret = otz_client_shared_mem_alloc(file->private_data, argp);
//        mutex_unlock(&mem_alloc_lock);
//        if (ret)
//            TDEBUG("failed otz_client_shared_mem_alloc: %d", ret);
//        break;
//    }
//    case OTZ_CLIENT_IOCTL_SHR_MEM_FREE_REQ: {
//        /* Only one client allowed here at a time */
//        mutex_lock(&mem_free_lock);
//        ret = otz_client_shared_mem_free(file->private_data, argp);
//        mutex_unlock(&mem_free_lock);
//        if (ret)
//            TDEBUG("failed otz_client_shared_mem_free: %d", ret);
//        break;
//    }
//    case OTZ_CLIENT_IOCTL_OPERATION_RELEASE: {
//        ret = otz_client_operation_release(file->private_data, argp);
//        if (ret)
//            TDEBUG("failed operation release: %d", ret);
//        break;
//    }
    default:
        return -EINVAL;
    }
    return ret;
}

/**
 * @brief
 *
 * @param inode
 * @param file
 *
 * @return
 */
static int tee_driver_open(struct inode *inode, struct file *file)
{
    int ret;
    teec_dev_file_t *new_dev;

    device_file_cnt++;
    file->private_data = (void*)device_file_cnt;

    new_dev = (teec_dev_file_t*)kmalloc(sizeof(teec_dev_file_t), GFP_KERNEL);
    if(!new_dev){
       TERR("kmalloc failed for new dev file allocation ");
       ret = -ENOMEM;
       goto ret_func;
    }

    new_dev->dev_file_id = device_file_cnt;
    new_dev->service_cnt = 0;
    INIT_LIST_HEAD(&new_dev->services_list);

    // Initialize the new_dev->dev_shared_mem_head
	memset(&new_dev->dev_shared_mem_head, 0, sizeof(teec_shared_mem_head_t));
    new_dev->dev_shared_mem_head.shared_mem_cnt = 0; // Redundant
    INIT_LIST_HEAD(&new_dev->dev_shared_mem_head.shared_mem_list);


    list_add(&new_dev->head, &teec_dev_file_head.dev_file_list);
    teec_dev_file_head.dev_file_cnt++;

    // TODO Init sevices, it should not be done like that.
    if((ret = tee_client_service_init(new_dev, TEE_SVC_DRM)) != 0) {
    	TERR("Services initialization fail ");
        goto ret_func;
    }

    TDEBUG("TEE device file open and services initialized");

ret_func:
    return ret;
}

/**
 * @brief
 *
 * @param inode
 * @param file
 *
 * @return
 */
static int tee_driver_release(struct inode *inode, struct file *file)
{
//        u32 dev_file_id = (u32)file->private_data;
//
//
//    TDEBUG("otz_client_release ");
//    otz_client_service_exit(file->private_data);
//    if(list_empty(&otzc_dev_file_head.dev_file_list)){
//
//    }
    return 0;
}

/**
 * @brief Init tee
 *
 * @return
 */
static int tee_driver_smc_init(void)
{
    u32 ctr;

    // Read cache type from coprocesor cp15 and store value on ctr
    asm volatile("mrc p15, 0, %0, c0, c0, 1" : "=r" (ctr));

    // Select DMinLine from Cache type register
    cacheline_size =  4 << ((ctr >> 16) & 0xf);

    return 0;
}


/**
 * @brief
 */
static const struct file_operations tee_driver_fops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = tee_driver_ioctl,
        .open = tee_driver_open,
        .mmap = tee_driver_mmap,
        .release = tee_driver_release
};

/**
 * @brief
 *
 * @return
 */
static int __init tee_driver_init(void)
{
    int ret_code = 0;
    struct device *class_dev;

    TDEBUG("Init tee driver");
    tee_driver_smc_init();

    // Connecting device file with device driver
    // Registering for the <freemajor, 0> range of 1 device files with name TEE_DRIVER_DEV
    ret_code = alloc_chrdev_region(&tee_driver_device_no, 0, 1,
    		TEE_DRIVER_DEV);
    if (ret_code < 0) {

        TERR("alloc_chrdev_region failed %d", ret_code);
        return ret_code;
    }

    // Create and populate device class information
    driver_class = class_create(THIS_MODULE, TEE_DRIVER_DEV);
    if (IS_ERR(driver_class)) {
        ret_code = -ENOMEM;
        TERR("class_create failed %d", ret_code);
        goto unregister_chrdev_region;
    }

    // Create and populate  device info under the previous created class
    class_dev = device_create(driver_class, NULL, tee_driver_device_no, NULL,
    		TEE_DRIVER_DEV);
    if (!class_dev) {
        TERR("class_device_create failed %d", ret_code);
        ret_code = -ENOMEM;
        goto class_destroy;
    }

    cdev_init(&tee_driver_cdev, &tee_driver_fops);
    tee_driver_cdev.owner = THIS_MODULE;

    ret_code = cdev_add(&tee_driver_cdev,
                        MKDEV(MAJOR(tee_driver_device_no), 0), 1);
    if (ret_code < 0) {
        TERR("cdev_add failed %d", ret_code);
        goto class_device_destroy;
    }

    /* TODO Initialize structure for services and sessions*/
    TDEBUG("Initializing list for services ");
    memset(&teec_dev_file_head, 0, sizeof(teec_dev_file_head_t));
    teec_dev_file_head.dev_file_cnt = 0;
    INIT_LIST_HEAD(&teec_dev_file_head.dev_file_list);

    TDEBUG("Driver initialization OK ");
    goto return_fn;

class_device_destroy:
    device_destroy(driver_class, tee_driver_device_no);
class_destroy:
    class_destroy(driver_class);
unregister_chrdev_region:
    unregister_chrdev_region(tee_driver_device_no, 1);
return_fn:
    return ret_code;
}

/**
 * @brief
 */
static void __exit tee_driver_exit(void)
{
    TDEBUG("tee_driver exit");

    device_destroy(driver_class, tee_driver_device_no);
    class_destroy(driver_class);
    unregister_chrdev_region(tee_driver_device_no, 1);
}


MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Pablo Anton  <pablo.anton-del-pino@technicolor.com>");
MODULE_DESCRIPTION("TEE TrustZone Communicator");
MODULE_VERSION("1.00");

module_init(tee_driver_init);

module_exit(tee_driver_exit);

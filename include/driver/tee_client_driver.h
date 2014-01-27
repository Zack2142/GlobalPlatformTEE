/*
 * TEE Client API Implmentation:
 *
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
 * Header file for driver dependent  TEE Client API
 */
#ifndef __TEE_CLIENT_DRIVER_H_
#define __TEE_CLIENT_DRIVER_H_

#include <driver/tee_client_driver_common.h>

#define TEE_DRIVER_DEV "tee"


#define TEE_1K_SIZE 1024
#define TEE_MAX_REQ_PARAMS  12
#define TEE_MAX_RES_PARAMS  4


#undef TDEBUG
#ifdef TEE_DRIVER_DEBUG
#define TDEBUG(msg, args...) printk(KERN_INFO "TEE-Driver: %s(%i, %s) - " msg "\n",\
		__func__, current->pid, current->comm, ## args)
#else
#define TDEBUG(msg, args...)
#endif

#undef TERR
#define TERR(msg, args...) printk(KERN_ERR "TEE-Driver: %s(%i, %s): " msg "\n",\
		__func__, current->pid, current->comm, ## args)

/**
 * @brief Encoding data type
 */
enum tee_enc_data_type {
    TEE_ENC_INVALID_TYPE = 0,
    TEE_ENC_UINT32,
    TEE_ENC_ARRAY,
    TEE_MEM_REF,
    TEE_SECURE_MEM_REF
};

/**
 * @brief
 */
typedef struct teec_dev_file_head_t{
    u32 dev_file_cnt;
    struct list_head dev_file_list;
} teec_dev_file_head_t;


/**
 * @brief
 */
typedef struct teec_shared_mem_head_t{
    int shared_mem_cnt;
    struct list_head shared_mem_list;
} teec_shared_mem_head_t;


/**
 * @brief
 */
typedef struct teec_dev_file_t{
    struct list_head head;
    u32 dev_file_id;
    u32 service_cnt;
    struct list_head services_list;
    teec_shared_mem_head_t dev_shared_mem_head;
} teec_dev_file_t;


/**
 * @brief typedef that represent a TEE Service
 */
typedef struct teec_service_t{
    struct list_head head;
    u32 service_id;
    struct list_head sessions_list;
} teec_service_t;

/**
 * @brief
 */
typedef struct teec_session_t{
    struct list_head head;
    int session_id;

    struct list_head encode_list;
    struct list_head shared_mem_list;
} teec_session_t;


/**
 * @brief
 */
typedef struct tee_wait_data_t {
    wait_queue_head_t send_cmd_wq;
    int               send_wait_flag;
}tee_wait_data_t;


/**
 * @brief Metadata used for encoding/decoding
 */
typedef struct teec_encode_meta_t {
    int type;
    int len;
    unsigned int usr_addr;
    int ret_len;
}teec_encode_meta_t;

/**
 * @brief
 */
typedef struct teec_encode_t{

    struct list_head head;

    int encode_id;

    void* ker_req_data_addr;
    void* ker_res_data_addr;

    u32  enc_req_offset;
    u32  enc_res_offset;
    u32  enc_req_pos;
    u32  enc_res_pos;
    u32  dec_res_pos;

    u32  dec_offset;

    tee_wait_data_t wait_data;

    teec_encode_meta_t *meta;
} teec_encode_t;


#endif

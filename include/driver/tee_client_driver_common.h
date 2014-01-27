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
 * Trustzone client driver defintions. This definitions should be user both the
 * libraries that interacts with the driver and the TEE Server (Genode in our case)
 */
#ifndef __TEE_CLIENT_DRIVER_COMMON_H_
#define __TEE_CLIENT_DRIVER_COMMON_H_

#define SMC_ENOMEM          7
#define SMC_EOPNOTSUPP      6
#define SMC_EINVAL_ADDR     5
#define SMC_EINVAL_ARG      4
#define SMC_ERROR           3
#define SMC_INTERRUPTED     2
#define SMC_PENDING         1
#define SMC_SUCCESS         0


#define TEE_CLIENT_FULL_PATH_DEV_NAME "/dev/tee"


#define CALL_TEE_API		1 	// Value for r0 when smc

/*
 * Value for r2 when calling smc from client or server TEE API
 */
enum tee_cmd_type {
	TEE_CMD_TYPE_INVALID = 0,
	TEE_CMD_TYPE_NS_TO_SECURE,
	TEE_CMD_TYPE_SECURE_TO_NS,
	TEE_CMD_TYPE_SECURE_TO_SECURE,
	TEE_CMD_TYPE_MAX  = 0x7FFFFFFF
};

/**
 * @brief Parameters type
 */
enum teec_param_type {
    TEEC_PARAM_IN = 0,
    TEEC_PARAM_OUT
};

/**
 * @brief SMC command structure
 */
typedef struct tee_smc_cmd_t {
	unsigned int    cmd_id;				// Command ID
    unsigned int    context;		// Context of which command belong to
    unsigned int    enc_id;

    unsigned int    svc_id;			// Service ID
    unsigned int    src_context;

    unsigned int    req_buf_len;	// Request buffer lenght for Request Buffer command
    unsigned int    resp_buf_len;	// Respond buffer lenght for Request Buffer command
    unsigned int    ret_resp_buf_len;
    unsigned int    cmd_status;		// Status of the command
    unsigned int    req_buf_phys;
    unsigned int    resp_buf_phys;
    unsigned int    meta_data_phys;
    unsigned int    dev_file_id;
}tee_smc_cmd_t;


/**
 * @brief Encode command structure
 */
typedef struct tee_client_encode_cmd_t {
    unsigned int len;
    void* data;
    int   offset;
    int   flags;
    int   param_type;

    int encode_id;
    int service_id;
    int session_id;
    unsigned int cmd_id;
} tee_client_encode_cmd_t;

/**
 * @brief Command ID's for global service
 */
enum tee_global_cmd_id {
    TEE_GLOBAL_CMD_ID_INVALID 				= 0x0,
    TEE_SVC_GLOBAL 							= 0x00000200,
    TEE_SVC_GLOBAL_CMD_ID_BOOT_ACK			= 0x00000201,
    TEE_SVC_GLOBAL_CMD_ID_OPEN_SESSION		= 0x00000202,
    TEE_SVC_GLOBAL_CMD_ID_CLOSE_SESSION		= 0x00000203,
    TEE_SVC_GLOBAL_CMD_ID_RESUME_ASYNC_TASK	= 0x00000204,
    TEE_SVC_GLOBAL_CMD_ID_UNKNOWN         	= 0x7FFFFFFE,
    TEE_SVC_GLOBAL_CMD_ID_MAX             	= 0x7FFFFFFF
};

enum tee_drm_cmd_id {
	TEE_SVC_DRM_CMD_ID_INVALID = 0x0,
	TEE_SVC_DRM = 0x00000100,
	TEE_SVC_DRM_CMD_ID_DECRYPT_PACK = 0x00000101
};

/**
 * @brief Metadata used for encoding/decoding
 */
struct teec_encode_meta {
    int type;
    int len;
    unsigned int usr_addr;
    int ret_len;
};

/**
 * @brief Session details structure
 */
typedef struct service_session_id_t{
    int service_id;
    int session_id;
}service_session_id_t;

/**
 * @brief Shared memory information for the session
 */
typedef struct tee_session_shared_mem_info_t{
    int service_id;
    int session_id;
    unsigned int user_mem_addr;
}tee_session_shared_mem_info_t;


#define TEE_CLIENT_IOC_MAGIC 0x775B777F /* "OTZ Client" */

/* For general service */
#define TEE_CLIENT_IOCTL_SES_OPEN_REQ \
    _IOW(TEE_CLIENT_IOC_MAGIC, 4,  service_session_id_t )
#define TEE_CLIENT_IOCTL_SES_CLOSE_REQ \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 5, service_session_id_t)

#define TEE_CLIENT_IOCTL_SHR_MEM_FREE_REQ \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 6, tee_session_shared_mem_info_t )
#define TEE_CLIENT_IOCTL_SEND_CMD_REQ \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 3, tee_client_encode_cmd_t)
#define TEE_CLIENT_IOCTL_ENC_UINT32 \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 7, tee_client_encode_cmd_t)
#define TEE_CLIENT_IOCTL_ENC_ARRAY \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 8, tee_client_encode_cmd_t)
#define TEE_CLIENT_IOCTL_ENC_ARRAY_SPACE \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 9, tee_client_encode_cmd_t)
#define TEE_CLIENT_IOCTL_ENC_MEM_REF \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 10, tee_client_encode_cmd_t)

#define TEE_CLIENT_IOCTL_DEC_UINT32 \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 11, tee_client_encode_cmd_t)
#define TEE_CLIENT_IOCTL_DEC_ARRAY_SPACE \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 12, tee_client_encode_cmd_t)
#define TEE_CLIENT_IOCTL_OPERATION_RELEASE \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 13, tee_client_encode_cmd_t)
#define TEE_CLIENT_IOCTL_SHR_MEM_ALLOCATE_REQ \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 14, tee_session_shared_mem_info_t)
#define TEE_CLIENT_IOCTL_GET_DECODE_TYPE \
    _IOWR(TEE_CLIENT_IOC_MAGIC, 15, tee_client_encode_cmd_t)

#endif

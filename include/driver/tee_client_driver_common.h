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

#define SMC_ENOMEM          7
#define SMC_EOPNOTSUPP      6
#define SMC_EINVAL_ADDR     5
#define SMC_EINVAL_ARG      4
#define SMC_ERROR           3
#define SMC_INTERRUPTED     2
#define SMC_PENDING         1
#define SMC_SUCCESS         0

#define TEE_DRIVER_CMD		1 // Value for r0 when smc


/**
 * @brief SMC command structure
 */
typedef struct tee_smc_cmd {
	unsigned int    id;				// Identifier
    unsigned int    context;		// Context of which command belong to
    unsigned int    enc_id;

    unsigned int    src_id;			// Service ID
    unsigned int    src_context;

    unsigned int    req_buf_len;	// Request buffer lenght for Request Buffer command
    unsigned int    resp_buf_len;	// Respond buffer lenght for Request Buffer command
    unsigned int    ret_resp_buf_len;
    unsigned int    cmd_status;		// Status of the command
    unsigned int    req_buf_phys;
    unsigned int    resp_buf_phys;
    unsigned int    meta_data_phys;
    unsigned int    dev_file_id;
}tee_smc_cmd;

/**
 * @brief Command ID's for global service
 */
enum tee_global_cmd_id {
    TEE_GLOBAL_CMD_ID_INVALID = 0x0,
    TEE_GLOBAL_CMD_ID_BOOT_ACK,
    TEE_GLOBAL_CMD_ID_OPEN_SESSION,
    TEE_GLOBAL_CMD_ID_CLOSE_SESSION,
    TEE_GLOBAL_CMD_ID_RESUME_ASYNC_TASK,
    TEE_GLOBAL_CMD_ID_UNKNOWN         = 0x7FFFFFFE,
    TEE_GLOBAL_CMD_ID_MAX             = 0x7FFFFFFF
};

enum tee_drm_cmd_id {
	TEE_DRM_CMD_ID_INVALID = 0x0,
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


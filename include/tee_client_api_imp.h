/*
 * TEE Client API Implmentation
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
 * Header file for implementation dependent  TEE Client API
 */
#ifndef __TEE_CLIENT_API_IMP_H_
#define __TEE_CLIENT_API_IMP_H_

#include <stdint.h>
#include <list.h>

#define TEE_DEBUG

#define TYPE_UINT_DEFINED 1

#define MAX_SESSIONS_PER_DEVICE 16
#define MAX_OPERATIONS_PER_SESSION 16
#define MAX_MEMBLOCKS_PER_SESSION 16
#define MAX_MEMBLOCKS_PER_OPERATION 4

#define TEEC_PARAM_TYPES( param0Type, param1Type, param2Type, param3Type) \
    (param3Type << 12 | param2Type << 8 | param1Type << 4 | param0Type)

#define TEEC_VALUE_UNDEF 0xffffffff


typedef struct	TEEC_IMP_Context {
	/*! Device identifier */
    uint32_t fd;
    /*! Sessions count of the device */
    int session_count;
    /*! Shared memory counter which got created for this context */
    uint32_t shared_mem_cnt;
    /*! Shared memory list */
    struct list_head shared_mem_list;
    /*! Error number from the client driver */
    int s_errno;
}TEEC_IMP_Context;

typedef struct	TEEC_IMP_Session {
/*! Implementation-defined variables */
/*! Reference count of operations*/
    int operation_cnt;
/*! Session id obtained for the  service*/
    int session_id;
/*! Unique service id */
    int service_id;
/*! Device context */
    TEEC_IMP_Context* device;
/*! Service error number */
    int s_errno;
}TEEC_IMP_Session;

/**
* @brief Shared memory flag constants
*
*
*/
enum tee_shared_mem_flags {
/*! Service can only read from the memory block.*/
    TEE_MEM_SERVICE_RO = 0x0,
/*! Service can only write from the memory block.*/
    TEE_MEM_SERVICE_WO ,
/*! Service can read and write from the memory block.*/
    TEE_MEM_SERVICE_RW,
/*! Invalid flag */
    TEE_MEM_SERVICE_UNDEFINED
};

#endif //__TEE_CLIENT_API_IMP_H_

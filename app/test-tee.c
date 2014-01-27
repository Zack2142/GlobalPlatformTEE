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
 * Test App for check the library and driver functionality
 */
#include <stdio.h>
#include <tee_client_api.h>
#include <driver/tee_client_driver_common.h>

int main(int argc, char* argv[])
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_SharedMemory shareMem;
	TEEC_Result result;

	printf("Utilizando el driver \n");
	TEEC_UUID svc_id = TEE_SVC_DRM;

	uint32_t len;
	char    testData[256];

	result = TEEC_InitializeContext(
			NULL,
			&context);

	if(result != TEEC_SUCCESS) {
			goto cleanup_1;
	}

	result = TEEC_OpenSession(
			&context,
			&session,
			&svc_id,
			TEEC_LOGIN_PUBLIC,
			NULL,
			NULL,
			NULL);

	if(result != TEEC_SUCCESS) {
		goto cleanup_2;
	}


	printf("session id 0x%x\n", session.imp.session_id);

	shareMem.size = 10000;
	shareMem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT ;

	result = TEEC_AllocateSharedMemory(
			&context,
			&shareMem);

	if(result != TEEC_SUCCESS) {
			goto cleanup_2;
	}

	// Configure operation fields
	operation.started 	= 1;				// No cancel operation
	operation.paramTypes= TEEC_PARAM_TYPES( // Type of parameters
			TEEC_NONE,
			TEEC_NONE,
			TEEC_NONE,
			TEEC_NONE);

//	TEEC_Parameter param;
//
//	param.tmpref.buffer= (void*)pkt->data;
//	param.tmpref.size 	= pkt->size;

	result = TEEC_InvokeCommand(
			&session,
			TEE_SVC_DRM_CMD_ID_DECRYPT_PACK,
			&operation,
			NULL);
	if (result != TEEC_SUCCESS)
	{
		goto cleanup_3;
	}

	printf("command success\n");
	cleanup_3:
	TEEC_CloseSession(&session);
	cleanup_2:
	TEEC_FinalizeContext(&context);
	cleanup_1:
	return 0;

}

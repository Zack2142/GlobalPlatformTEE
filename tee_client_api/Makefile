# Makefile to compile TEE Client API library and generate
# libteeclientapi.so
CFLAGS=-g -mcpu=cortex-a8 -fPIC -DTEE_LIB_DEBUG


ifdef CROSS_COMPILE
	gcc := ${CROSS_COMPILE}gcc
	ld	:= ${CROSS_COMPILE}ld
else
	gcc := gcc
	ld	:= ld
endif

target 	= ../build/libteeclientapi.so
source 	= tee_client_api.c
objs 		= tee_client_api.o
deploy_target_dir :=  ${DEPLOY_DIR}usr/lib/

deploy: build
	@cp -ap ${target} ${deploy_target_dir} 
	
build: ${target}

${target}: ${source}
	${gcc} ${CFLAGS} -I${INCLUDE_DIR} -c -o ${objs}  ${source}
	${ld} -o ${target} ${objs} -shared 
	@rm -f ${objs}
	
	
clean:
	@rm -f ${objs}
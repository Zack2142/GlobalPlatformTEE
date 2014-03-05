# Makefile to compile TEE Client API Test aplication 
CFLAGS= -g -mcpu=cortex-a8

ifdef CROSS_COMPILE
	gcc := ${CROSS_COMPILE}gcc
	ld	:= ${CROSS_COMPILE}ld
else
	gcc := gcc
	ld	:= ld
endif

target 	= ../build/test-tee
source 	= test-tee.c
objs 		= test-tee.o
deploy_target_dir :=  ${DEPLOY_DIR}usr/bin

lib_dir	= ../build/

deploy: build
	@cp -ap ${target} ${deploy_target_dir} 
	
build: ${target}
ifeq ($(USER),root)
	@chown -R pablo:pablo ${target}
endif

${target}: ${source}
	${gcc} ${CFLAGS} -I${INCLUDE_DIR} -L${lib_dir} -o ${target} ${source} -Bdynamic -lteeclientapi
	
clean:
	@rm -f ${objs}
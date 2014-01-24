# General Makefile to build driver, linux library and example app.
# Export variable to handler crosscompiling
export CROSS_COMPILE=/home/pablo/x-tools/arm-cortex_a8-linux-gnueabi/bin/arm-cortex_a8-linux-gnueabi-
export ARCH=arm

export BASE_DIR=$(shell pwd)
export BUILD_DIR=${BASE_DIR}/build
export DRIVER_SOURCE_DIR=${BASE_DIR}/driver
export INCLUDE_DIR=${BASE_DIR}/include
export LIB_SOURCE_DIR=${BASE_DIR}/tee_client_api
export KERNEL_SOURCE=/home/pablo/dev/git/linux
export APP_SOURCE_DIR=${BASE_DIR}/app

deploy: clean all
	${MAKE} -C ${DRIVER_SOURCE_DIR} deploy
	${MAKE} -C ${LIB_SOURCE_DIR} deploy
	${MAKE} -C ${APP_SOURCE_DIR} deploy

all:
	${MAKE} -C ${DRIVER_SOURCE_DIR} build
	${MAKE} -C ${LIB_SOURCE_DIR} build
	${MAKE} -C ${APP_SOURCE_DIR} build
	
clean:
	${MAKE} -C ${DRIVER_SOURCE_DIR} clean
	${MAKE} -C ${LIB_SOURCE_DIR} clean
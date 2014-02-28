# General Makefile to build driver, linux library and example app.
# Export variable to handler crosscompiling
export CROSS_COMPILE=/home/pablo/x-tools/arm-cortex_a8-linux-gnueabi/bin/arm-cortex_a8-linux-gnueabi-
export KERNEL_SOURCE=/home/pablo/ltib/rpm/BUILD/linux-2.6.35.3/
export KERNEL_BUILD_DIR=build
export DEPLOY_DIR=/media/9a195aaa-13bd-4b47-a74c-e77c09256265/

export ARCH=arm

export BASE_DIR=$(shell pwd)
export BUILD_DIR=${BASE_DIR}/build
export DRIVER_SOURCE_DIR=${BASE_DIR}/driver
export INCLUDE_DIR=${BASE_DIR}/include
export LIB_SOURCE_DIR=${BASE_DIR}/tee_client_api
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
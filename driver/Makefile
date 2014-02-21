# Makefile – makefile for TEE Client Driver implementing with TrustZone
#
obj-m := tee_client_driver.o

ccflags-y := -I${INCLUDE_DIR}

target 	= ${BUILD_DIR}/tee_client_driver.ko
deploy_target_dir :=  ${DEPLOY_DIR}lib/modules/tee-driver-1.0.0/
source = ${DRIVER_SOURCE_DIR}/tee_client_driver.c

deploy: build 
	@mkdir -p ${deploy_target_dir}
	@cp -ap ${target} ${deploy_target_dir}
	
build: ${target}

#KCPPFLAGS="-DTEE_DRIVER_DEBUG" 
${target}: ${source}
	${MAKE} -C ${KERNEL_SOURCE} O=build SUBDIRS=${DRIVER_SOURCE_DIR} modules
	@mv *.o ${BUILD_DIR}
	@mv *.ko ${BUILD_DIR}
	@mv *.symvers ${BUILD_DIR}
	@mv *.order ${BUILD_DIR}
	@mv *.mod.c ${BUILD_DIR}
	@chown -R pablo:pablo ${BUILD_DIR}/
	@chown -R pablo:pablo ${DRIVER_SOURCE_DIR}/
	
clean:
	${MAKE} -C ${KERNEL_SOURCE} O=build SUBDIRS=${DRIVER_SOURCE_DIR} clean
	echo ${BUILD_DIR}
	@rm -f ${BUILD_DIR}/*
	
	
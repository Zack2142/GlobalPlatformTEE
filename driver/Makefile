# Makefile – makefile for TEE Client Driver implementing with TrustZone
#

# if KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq (${KERNELRELEASE},)
    obj-m := teeDriver.o
    
# Otherwise we were called directly from the command line.
# Invoke the kernel.
else
    KERNEL_SOURCE := /home/pablo/dev/git/linux/
    PWD := $(shell pwd)
    
default:
    ${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules
 
clean:
    ${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean
endif
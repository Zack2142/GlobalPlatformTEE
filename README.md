GlobalPlatformTEE
=================

Adaptation of Global Platform TEE Client API based on OpenVirtualization implementation.

Compilation error
=================
ERROR: Kernel configuration is invalid.
         include/generated/autoconf.h or include/config/auto.conf are missing.
         Run 'make oldconfig && make prepare' on kernel src to fix it.

Make sure the linux src is configured in any directory and set KERNEL_SOURCE value to that directory or specify option O=buildDir.

Execution error
=================
It could be several different errors when  you try execute the driver. Make sure you compile the drivers agains the same version of linux where you run it later.

#include <linux/list.h>

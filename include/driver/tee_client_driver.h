/*
 * TEE Client API Implmentation:
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
 * Header file for driver dependent  TEE Client API
 */
#ifndef __TEE_CLIENT_DRIVER_H_
#define __TEE_CLIENT_DRIVER_H_


#define TEE_DRIVER_DEV "tee_driver"

#undef TDEBUG
#ifdef TEE_DRIVER_DEBUG
#define TDEBUG(msg, args...) printk(KERN_INFO "TEE-Driver: %s(%i, %s) - " msg "\n",\
		__func__, current->pid, current->comm, ## args)
#else
#define TDEBUG(msg, args...)
#endif

#undef TERR
#define TERR(msg, args...) printk(KERN_DEBUG "TEE-Driver: %s(%i, %s): " msg "\n",\
		__func__, current->pid, current->comm, ## args)

#endif

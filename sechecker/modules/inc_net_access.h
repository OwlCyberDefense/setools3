/**
 *  @file inc_net_access.h
 *  Defines the interface for the incomplete network access module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author David Windsor dwindsor@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef inc_net_access_H
#define inc_net_access_H

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/avrule-query.h>

#define inc_net_access_ERR -1
#define inc_net_access_SUCCESS 0
#define inc_net_access_FAIL 1
#define inc_net_access_HAVE_PERMS 0
#define inc_net_access_NEEDED_PERMS 1


/* used for lookup of idx's */
typedef struct idx_cache {
	int TCP_SOCKET_OBJ;
	int UDP_SOCKET_OBJ;
	int NODE_OBJ;
	int NETIF_OBJ;
	int ASSOC_OBJ;
	int CREATE_PERM;
	int READ_PERM;
	int WRITE_PERM;
	int TCP_RECV_PERM;
	int TCP_SEND_PERM;
	int UDP_RECV_PERM;
	int UDP_SEND_PERM;
	int RECV_MSG_PERM;
	int SEND_MSG_PERM;
	int RECVFROM_PERM;
	int SENDTO_PERM;
} idx_cache_t;

/* The inc_net_access_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct inc_net_access_data {
	bool_t SELF_TCPSOCK_CREATE;
	bool_t SELF_UDPSOCK_CREATE;
	bool_t SELF_TCPSOCK_READ;
	bool_t SELF_TCPSOCK_WRITE;
	bool_t SELF_UDPSOCK_READ;
	bool_t SELF_UDPSOCK_WRITE;
	bool_t ANY_NETIF_TCPRECV;
	bool_t ANY_NETIF_TCPSEND;
	bool_t ANY_NETIF_UDPRECV;
	bool_t ANY_NETIF_UDPSEND;
	bool_t PORT_TCPSOCK_RECVMSG;
	bool_t PORT_TCPSOCK_SENDMSG;
	bool_t PORT_UDPSOCK_RECVMSG;
	bool_t PORT_UDPSOCK_SENDMSG;
	bool_t ANY_NODE_TCPRECV;
	bool_t ANY_NODE_TCPSEND;
	bool_t ANY_NODE_UDPRECV;
	bool_t ANY_NODE_UDPSEND;
	bool_t ANY_ASSOC_RECVFROM;
	bool_t ANY_ASSOC_SENDTO;
	idx_cache_t idx_cache;
} inc_net_access_data_t;

inc_net_access_data_t *inc_net_access_data_new(void);
void inc_net_access_data_free(void *data);

/* Module functions:
 * Do not change any of these prototypes or you will not be
 * able to run the module in the library */
int inc_net_access_register(sechk_lib_t *lib);
int inc_net_access_init(sechk_module_t *mod, apol_policy_t *policy, void *arg);
int inc_net_access_run(sechk_module_t *mod, apol_policy_t *policy, void *arg);
int inc_net_access_print(sechk_module_t *mod, apol_policy_t *policy, void *arg);

#endif

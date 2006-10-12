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

#include "inc_net_access.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char *const mod_name = "inc_net_access";

/* The register function registers all of a module's functions
 * with the library.  You should not need to edit this function
 * unless you are adding additional functions you need other modules
 * to call. See the note at the bottom of this function to do so. */
int inc_net_access_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		errno = EINVAL;
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		errno = EINVAL;
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "finds network domains with inadequate permissions";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds all network domains in a policy which do not have the         \n"
		"required permissions needed to facilitate network communication. For network\n"
		"domains to communicate, the following conditions must be true:\n"
		"   1) the domain must have read or receive permissions on a socket of the same\n"
		"      type\n"
		"   2) the domain must have send or receive permissions on an IPsec association\n"
		"      (see find_assoc_types)\n"
		"   3) the domain must have send or receive permissions on netif objects for a\n"
		"      netif type (see find_netif_types)\n"
		"   4) the domain must have send or receive permissions on node objects for a\n"
		"      node type (see find_node_types)\n"
		"   5) the domain must have send or receive permissions on port objects for a\n"
		"      port type (see find_port_types)\n"; 
	mod->opt_description = 
		"  Module requirements:\n"
		"    policy source\n"
		"  Module dependencies:\n"
		"    find_net_domains module\n"
		"    find_assoc_types module\n"
		"    find_netif_types module\n"
		"    find_port_types module\n"
		"    find_node_types module\n"
		"  Module options:\n"
		"    none\n";
	mod->severity = SECHK_SEV_MED;
	/* assign dependencies */      
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_net_domains")) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_netif_types")) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_port_types")) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_node_types")) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_assoc_types")) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = inc_net_access_init;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = inc_net_access_run;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	mod->data_free = NULL;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = inc_net_access_print;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file.
 * Add any option processing logic as indicated below. */
int inc_net_access_init(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	if (!mod || !policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	mod->data = NULL;

	return 0;
}

/* This set of defines represents individual permission bits for
 * the permissions needed to have complete network access */
/* allow domain self : sock_file {read write getattr}; */
#define PERM_SELF_SOCK_FILE_READ    0x00000001
#define PERM_SELF_SOCK_FILE_WRITE   0x00000002
#define PERM_SELF_SOCK_FILE_GETATTR 0x00000004
/* allow domain self : tcp_socket {create read write}; */
#define PERM_SELF_TCP_SOC_READ      0x00000008
#define PERM_SELF_TCP_SOC_WRITE     0x00000010
#define PERM_SELF_TCP_SOC_CREATE    0x00000020
/* allow domain self : udp_socket {create read write}; */
#define PERM_SELF_UDP_SOC_READ      0x00000040
#define PERM_SELF_UDP_SOC_WRITE     0x00000080
#define PERM_SELF_UDP_SOC_CREATE    0x00000100
/* allow domain if_type : netif {tcp_send udp_send tcp_recv tcp_send}; */
#define PERM_NETIF_TCP_SEND         0x00000200
#define PERM_NETIF_UDP_SEND         0x00000400
#define PERM_NETIF_TCP_RECV         0x00000800
#define PERM_NETIF_UDP_RECV         0x00001000
/* allow domain node_type : node {tcp_send udp_send tcp_recv tcp_send}; */
#define PERM_NODE_TCP_SEND          0x00002000
#define PERM_NODE_UDP_SEND          0x00004000
#define PERM_NODE_TCP_RECV          0x00008000
#define PERM_NODE_UDP_RECV          0x00010000
/* allow domain port_type : tcp_socket {send_msg recv_msg}; */
#define PERM_PORT_TCP_SEND          0x00020000
#define PERM_PORT_TCP_RECV          0x00040000
/* allow domain port_type : udp_socket {send_msg recv_msg}; */
#define PERM_PORT_UDP_SEND          0x00080000
#define PERM_PORT_UDP_RECV          0x00100000
/* allow domain assoc_type : association {sendto recvfrom}; */
#define PERM_ASSOC_SEND             0x00200000
#define PERM_ASSOC_RECV             0x00400000

/* this set of defines represents masks for individual rules */
#define RULE_TCP_SOCK_FILE  (PERM_SELF_SOCK_FILE_READ|PERM_SELF_SOCK_FILE_WRITE|PERM_SELF_SOCK_FILE_GETATTR)
#define RULE_UDPs_SOCK_FILE (PERM_SELF_SOCK_FILE_WRITE|PERM_SELF_SOCK_FILE_GETATTR)
#define RULE_UDPr_SOCK_FILE (PERM_SELF_SOCK_FILE_READ|PERM_SELF_SOCK_FILE_GETATTR)
#define RULE_TCP_SELF_SOC   (PERM_SELF_TCP_SOC_READ|PERM_SELF_TCP_SOC_WRITE|PERM_SELF_TCP_SOC_CREATE)
#define RULE_UDPs_SELF_SOC  (PERM_SELF_UDP_SOC_WRITE|PERM_SELF_UDP_SOC_CREATE)
#define RULE_UDPr_SELF_SOC  (PERM_SELF_UDP_SOC_READ|PERM_SELF_UDP_SOC_CREATE)
#define RULE_TCP_NETIF      (PERM_NETIF_TCP_SEND|PERM_NETIF_TCP_RECV)
#define RULE_UDPs_NETIF     (PERM_NETIF_UDP_SEND)
#define RULE_UDPr_NETIF     (PERM_NETIF_UDP_RECV)
#define RULE_TCP_NODE       (PERM_NODE_TCP_SEND|PERM_NODE_TCP_RECV)
#define RULE_UDPs_NODE      (PERM_NODE_UDP_SEND)
#define RULE_UDPr_NODE      (PERM_NODE_UDP_RECV)
#define RULE_TCP_PORT       (PERM_PORT_TCP_SEND|PERM_PORT_TCP_RECV)
#define RULE_UDPs_PORT      (PERM_PORT_UDP_SEND)
#define RULE_UDPr_PORT      (PERM_PORT_UDP_RECV)
#define RULE_TCP_ASSOC      (PERM_ASSOC_SEND|PERM_ASSOC_RECV)
#define RULE_UDPs_ASSOC     (PERM_ASSOC_SEND)
#define RULE_UDPr_ASSOC     (PERM_ASSOC_RECV)

/* This set of defines represents mask sets to represent access types */
#define UDP_RECV_PERM_SET (RULE_UDPr_SOCK_FILE|RULE_UDPr_SELF_SOC|RULE_UDPr_NETIF|RULE_UDPr_NODE|RULE_UDPr_PORT|RULE_UDPr_ASSOC)
#define UDP_SEND_PERM_SET (RULE_UDPs_SOCK_FILE|RULE_UDPs_SELF_SOC|RULE_UDPs_NETIF|RULE_UDPs_NODE|RULE_UDPs_PORT|RULE_UDPs_ASSOC)
#define TCP_FULL_PERM_SET (RULE_TCP_SOCK_FILE|RULE_TCP_SELF_SOC|RULE_TCP_NETIF|RULE_TCP_NODE|RULE_TCP_PORT|RULE_TCP_ASSOC)
#define COMMON_ACCESS_SET (PERM_SELF_SOCK_FILE_READ|PERM_SELF_SOCK_FILE_WRITE|PERM_SELF_SOCK_FILE_GETATTR|PERM_ASSOC_SEND|PERM_ASSOC_RECV)

typedef struct net_state {
	uint32_t perms;
	apol_vector_t *netifs;
	apol_vector_t *nodes;
	apol_vector_t *tcpsocs;
	apol_vector_t *udpsocs;
	apol_vector_t *assocs;
} net_state_t;

typedef struct name_perm {
	char *name; /* will be from policy do not free */
	uint32_t perms;
} name_perm_t;

static void net_state_destroy(net_state_t **n)
{
	if (!n || !(*n))
		return;

	apol_vector_destroy(&((*n)->netifs), free);
	apol_vector_destroy(&((*n)->nodes), free);
	apol_vector_destroy(&((*n)->tcpsocs), free);
	apol_vector_destroy(&((*n)->udpsocs), free);
	apol_vector_destroy(&((*n)->assocs), free);
	free(*n);
	*n = NULL;
}

static net_state_t *net_state_create(void)
{
	net_state_t *n = NULL;

	n = calloc(1, sizeof(*n));
	n->netifs = apol_vector_create();
	n->nodes = apol_vector_create();
	n->tcpsocs = apol_vector_create();
	n->udpsocs = apol_vector_create();
	n->assocs = apol_vector_create();

	return n;
}

static int name_perm_comp(const void *a, const void *b, void *arg __attribute__((unused)))
{
	const name_perm_t *x = a;
	const name_perm_t *y = b;

	return strcmp(x->name, y->name);
}

static name_perm_t *name_perm_create(char *name)
{
	name_perm_t *np = NULL;

	np = calloc(1, sizeof(*np));
	np->name = name;

	return np;
}

static int name_perm_vector_has_incomplete_perms(apol_vector_t *v, uint32_t mask)
{
	uint32_t tmp;
	name_perm_t *np = NULL;
	size_t i = 0;

	if (!apol_vector_get_size(v))
		return 1;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		np = apol_vector_get_element(v, i);
		tmp = np->perms & mask;
		if (tmp != mask)
			return 1;
	}

	return 0;
}

static void name_perm_vector_add_perm(apol_vector_t *v, char *name, uint32_t perm)
{
	name_perm_t *np = NULL;
	size_t i = 0;
	int retv;

	np = name_perm_create(name);
	retv = apol_vector_get_index(v, np, name_perm_comp, NULL, &i);
	if (retv) {
		np->perms = perm;
		apol_vector_append(v, (void*)np);
	} else {
		free(np); /* already exists free temp one */
		np = apol_vector_get_element(v, i);
		np->perms |= perm;
	}
}

static char * generate_tcp_proof_text(const char *domain, net_state_t *state)
{
	char *text = NULL, *tmp = NULL;
	size_t text_sz = 0, i;
	uint32_t attempt = 0, missing = 0;
	name_perm_t *np = NULL;

	if (state->perms == TCP_FULL_PERM_SET) {
		if (apol_str_append(&text, &text_sz, "Domain has TCP access, but some accesses are incomplete."))
			goto err;
	} else {
		if (apol_str_append(&text, &text_sz, "Domain has incomplete TCP access."))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tsock_file permissions:"))
		goto err;
	attempt = state->perms & RULE_TCP_SOCK_FILE;
	missing = attempt ^ RULE_TCP_SOCK_FILE;
	asprintf(&tmp, "allow %s self : sock_file { ", domain);
	if (attempt) {
		if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (attempt & PERM_SELF_SOCK_FILE_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (attempt & PERM_SELF_SOCK_FILE_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (attempt & PERM_SELF_SOCK_FILE_GETATTR) {
			if (apol_str_append(&text, &text_sz, "getattr "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	if (missing) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (missing & PERM_SELF_SOCK_FILE_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (missing & PERM_SELF_SOCK_FILE_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (missing & PERM_SELF_SOCK_FILE_GETATTR) {
			if (apol_str_append(&text, &text_sz, "getattr "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	free(tmp);
	tmp = NULL;

	if (apol_str_append(&text, &text_sz, "\n\tsocket creation permissions:"))
		goto err;
	attempt = state->perms & RULE_TCP_SELF_SOC;
	missing = attempt ^ RULE_TCP_SELF_SOC;
	asprintf(&tmp, "allow %s self : tcp_socket { ", domain);
	if (attempt) {
		if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (attempt & PERM_SELF_TCP_SOC_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (attempt & PERM_SELF_TCP_SOC_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (attempt & PERM_SELF_TCP_SOC_CREATE) {
			if (apol_str_append(&text, &text_sz, "create "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	if (missing) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (missing & PERM_SELF_TCP_SOC_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (missing & PERM_SELF_TCP_SOC_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (missing & PERM_SELF_TCP_SOC_CREATE) {
			if (apol_str_append(&text, &text_sz, "create "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	free(tmp);
	tmp = NULL;

	if (apol_str_append(&text, &text_sz, "\n\tnetif permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->netifs); i++) {
		np = apol_vector_get_element(state->netifs, i);
		attempt = state->perms & RULE_TCP_NETIF;
		missing = attempt ^ RULE_TCP_NETIF;
		asprintf(&tmp, "allow %s %s : netif { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_NETIF_TCP_SEND) {
				if (apol_str_append(&text, &text_sz, "tcp_send "))
					goto err;
			}
			if (attempt & PERM_NETIF_TCP_RECV) {
				if (apol_str_append(&text, &text_sz, "tcp_recv "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_NETIF_TCP_SEND) {
				if (apol_str_append(&text, &text_sz, "tcp_send "))
					goto err;
			}
			if (missing & PERM_NETIF_TCP_RECV) {
				if (apol_str_append(&text, &text_sz, "tcp_recv "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->netifs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <netif_type> : netif { tcp_send tcp_recv };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tnode permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->nodes); i++) {
		np = apol_vector_get_element(state->nodes, i);
		attempt = state->perms & RULE_TCP_NODE;
		missing = attempt ^ RULE_TCP_NODE;
		asprintf(&tmp, "allow %s %s : node { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_NODE_TCP_SEND) {
				if (apol_str_append(&text, &text_sz, "tcp_send "))
					goto err;
			}
			if (attempt & PERM_NODE_TCP_RECV) {
				if (apol_str_append(&text, &text_sz, "tcp_recv "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_NODE_TCP_SEND) {
				if (apol_str_append(&text, &text_sz, "tcp_send "))
					goto err;
			}
			if (missing & PERM_NODE_TCP_RECV) {
				if (apol_str_append(&text, &text_sz, "tcp_recv "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->nodes)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <node_type> : node { tcp_send tcp_recv };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tport socket permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->tcpsocs); i++) {
		np = apol_vector_get_element(state->tcpsocs, i);
		attempt = state->perms & RULE_TCP_PORT;
		missing = attempt ^ RULE_TCP_PORT;
		asprintf(&tmp, "allow %s %s : tcp_socket { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_PORT_TCP_SEND) {
				if (apol_str_append(&text, &text_sz, "send_msg "))
					goto err;
			}
			if (attempt & PERM_PORT_TCP_RECV) {
				if (apol_str_append(&text, &text_sz, "recv_msg "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_PORT_TCP_SEND) {
				if (apol_str_append(&text, &text_sz, "send_msg "))
					goto err;
			}
			if (missing & PERM_PORT_TCP_RECV) {
				if (apol_str_append(&text, &text_sz, "recv_msg "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->tcpsocs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <port_type> : tcp_socket { send_msg recv_msg };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tassociation permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->assocs); i++) {
		np = apol_vector_get_element(state->assocs, i);
		attempt = state->perms & RULE_TCP_ASSOC;
		missing = attempt ^ RULE_TCP_ASSOC;
		asprintf(&tmp, "allow %s %s : association { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_ASSOC_SEND) {
				if (apol_str_append(&text, &text_sz, "sendto "))
					goto err;
			}
			if (attempt & PERM_ASSOC_RECV) {
				if (apol_str_append(&text, &text_sz, "recvfrom "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_ASSOC_SEND) {
				if (apol_str_append(&text, &text_sz, "sendto "))
					goto err;
			}
			if (missing & PERM_ASSOC_RECV) {
				if (apol_str_append(&text, &text_sz, "recvfrom "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->assocs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <association_type> : association { sendto recvfrom };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n"))
		goto err;

	return text;

err:
	free(text);
	free(tmp);
	return NULL;
}

static char *generate_udp_send_proof_text(const char *domain, net_state_t *state)
{
	char *text = NULL, *tmp = NULL;
	size_t text_sz = 0, i;
	uint32_t attempt = 0, missing = 0;
	name_perm_t *np = NULL;

	if (state->perms == UDP_SEND_PERM_SET) {
		if (apol_str_append(&text, &text_sz, "Domain has UDP send access, but some accesses are incomplete."))
			goto err;
	} else {
		if (apol_str_append(&text, &text_sz, "Domain has incomplete UDP send access."))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tsock_file permissions:"))
		goto err;
	attempt = state->perms & RULE_UDPs_SOCK_FILE;
	missing = attempt ^ RULE_UDPs_SOCK_FILE;
	asprintf(&tmp, "allow %s self : sock_file { ", domain);
	if (attempt) {
		if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (attempt & PERM_SELF_SOCK_FILE_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (attempt & PERM_SELF_SOCK_FILE_GETATTR) {
			if (apol_str_append(&text, &text_sz, "getattr "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	if (missing) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (missing & PERM_SELF_SOCK_FILE_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (missing & PERM_SELF_SOCK_FILE_GETATTR) {
			if (apol_str_append(&text, &text_sz, "getattr "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	free(tmp);
	tmp = NULL;

	if (apol_str_append(&text, &text_sz, "\n\tsocket creation permissions:"))
		goto err;
	attempt = state->perms & RULE_UDPs_SELF_SOC;
	missing = attempt ^ RULE_UDPs_SELF_SOC;
	asprintf(&tmp, "allow %s self : udp_socket { ", domain);
	if (attempt) {
		if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (attempt & PERM_SELF_UDP_SOC_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (attempt & PERM_SELF_UDP_SOC_CREATE) {
			if (apol_str_append(&text, &text_sz, "create "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	if (missing) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (missing & PERM_SELF_UDP_SOC_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (missing & PERM_SELF_UDP_SOC_CREATE) {
			if (apol_str_append(&text, &text_sz, "create "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	free(tmp);
	tmp = NULL;

	if (apol_str_append(&text, &text_sz, "\n\tnetif permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->netifs); i++) {
		np = apol_vector_get_element(state->netifs, i);
		attempt = state->perms & RULE_UDPs_NETIF;
		missing = attempt ^ RULE_UDPs_NETIF;
		asprintf(&tmp, "allow %s %s : netif { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_NETIF_UDP_SEND) {
				if (apol_str_append(&text, &text_sz, "udp_send "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_NETIF_UDP_SEND) {
				if (apol_str_append(&text, &text_sz, "udp_send "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->netifs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <netif_type> : netif { udp_send };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tnode permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->nodes); i++) {
		np = apol_vector_get_element(state->nodes, i);
		attempt = state->perms & RULE_UDPs_NODE;
		missing = attempt ^ RULE_UDPs_NODE;
		asprintf(&tmp, "allow %s %s : node { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_NODE_UDP_SEND) {
				if (apol_str_append(&text, &text_sz, "udp_send "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_NODE_UDP_SEND) {
				if (apol_str_append(&text, &text_sz, "udp_send "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->nodes)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <node_type> : node { udp_send };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tport socket permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->udpsocs); i++) {
		np = apol_vector_get_element(state->udpsocs, i);
		attempt = state->perms & RULE_UDPs_PORT;
		missing = attempt ^ RULE_UDPs_PORT;
		asprintf(&tmp, "allow %s %s : udp_socket { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_PORT_UDP_SEND) {
				if (apol_str_append(&text, &text_sz, "send_msg "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_PORT_UDP_SEND) {
				if (apol_str_append(&text, &text_sz, "send_msg "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->udpsocs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <port_type> : udp_socket { send_msg };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tassociation permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->assocs); i++) {
		np = apol_vector_get_element(state->assocs, i);
		attempt = state->perms & RULE_UDPs_ASSOC;
		missing = attempt ^ RULE_UDPs_ASSOC;
		asprintf(&tmp, "allow %s %s : association { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_ASSOC_SEND) {
				if (apol_str_append(&text, &text_sz, "sendto "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_ASSOC_SEND) {
				if (apol_str_append(&text, &text_sz, "sendto "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->assocs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <association_type> : association { sendto };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n"))
		goto err;

	return text;

err:
	free(text);
	free(tmp);
	return NULL;
}

static char *generate_udp_recv_proof_text(const char *domain, net_state_t *state)
{
	char *text = NULL, *tmp = NULL;
	size_t text_sz = 0, i;
	uint32_t attempt = 0, missing = 0;
	name_perm_t *np = NULL;

	if (state->perms == UDP_RECV_PERM_SET) {
		if (apol_str_append(&text, &text_sz, "Domain has UDP receive access, but some accesses are incomplete."))
			goto err;
	} else {
		if (apol_str_append(&text, &text_sz, "Domain has incomplete UDP receive access."))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tsock_file permissions:"))
		goto err;
	attempt = state->perms & RULE_UDPr_SOCK_FILE;
	missing = attempt ^ RULE_UDPr_SOCK_FILE;
	asprintf(&tmp, "allow %s self : sock_file { ", domain);
	if (attempt) {
		if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (attempt & PERM_SELF_SOCK_FILE_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (attempt & PERM_SELF_SOCK_FILE_GETATTR) {
			if (apol_str_append(&text, &text_sz, "getattr "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	if (missing) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (missing & PERM_SELF_SOCK_FILE_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (missing & PERM_SELF_SOCK_FILE_GETATTR) {
			if (apol_str_append(&text, &text_sz, "getattr "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	free(tmp);
	tmp = NULL;

	if (apol_str_append(&text, &text_sz, "\n\tsocket creation permissions:"))
		goto err;
	attempt = state->perms & RULE_UDPr_SELF_SOC;
	missing = attempt ^ RULE_UDPr_SELF_SOC;
	asprintf(&tmp, "allow %s self : udp_socket { ", domain);
	if (attempt) {
		if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (attempt & PERM_SELF_UDP_SOC_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (attempt & PERM_SELF_UDP_SOC_CREATE) {
			if (apol_str_append(&text, &text_sz, "create "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	if (missing) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (missing & PERM_SELF_UDP_SOC_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (missing & PERM_SELF_UDP_SOC_CREATE) {
			if (apol_str_append(&text, &text_sz, "create "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	free(tmp);
	tmp = NULL;

	if (apol_str_append(&text, &text_sz, "\n\tnetif permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->netifs); i++) {
		np = apol_vector_get_element(state->netifs, i);
		attempt = state->perms & RULE_UDPr_NETIF;
		missing = attempt ^ RULE_UDPr_NETIF;
		asprintf(&tmp, "allow %s %s : netif { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_NETIF_UDP_RECV) {
				if (apol_str_append(&text, &text_sz, "udp_recv "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_NETIF_UDP_RECV) {
				if (apol_str_append(&text, &text_sz, "udp_recv "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->netifs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <netif_type> : netif { udp_recv };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tnode permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->nodes); i++) {
		np = apol_vector_get_element(state->nodes, i);
		attempt = state->perms & RULE_UDPr_NODE;
		missing = attempt ^ RULE_UDPr_NODE;
		asprintf(&tmp, "allow %s %s : node { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_NODE_UDP_RECV) {
				if (apol_str_append(&text, &text_sz, "udp_recv "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_NODE_UDP_RECV) {
				if (apol_str_append(&text, &text_sz, "udp_recv "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->nodes)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <node_type> : node { udp_recv };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tport socket permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->udpsocs); i++) {
		np = apol_vector_get_element(state->udpsocs, i);
		attempt = state->perms & RULE_UDPr_PORT;
		missing = attempt ^ RULE_UDPr_PORT;
		asprintf(&tmp, "allow %s %s : udp_socket { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_PORT_UDP_RECV) {
				if (apol_str_append(&text, &text_sz, "recv_msg "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_PORT_UDP_RECV) {
				if (apol_str_append(&text, &text_sz, "recv_msg "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->udpsocs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <port_type> : udp_socket { recv_msg };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n\tassociation permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->assocs); i++) {
		np = apol_vector_get_element(state->assocs, i);
		attempt = state->perms & RULE_UDPr_ASSOC;
		missing = attempt ^ RULE_UDPr_ASSOC;
		asprintf(&tmp, "allow %s %s : association { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_ASSOC_RECV) {
				if (apol_str_append(&text, &text_sz, "recvfrom "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		if (missing) {
			if (apol_str_append(&text, &text_sz, "\n\t\tMissing: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (missing & PERM_ASSOC_RECV) {
				if (apol_str_append(&text, &text_sz, "recvfrom "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}
	if (!apol_vector_get_size(state->assocs)) {
		if (apol_str_append(&text, &text_sz, "\n\t\tMissing: allow "))
			goto err;
		if (apol_str_append(&text, &text_sz, domain))
			goto err;
		if (apol_str_append(&text, &text_sz, " <association_type> : association { recvfrom };"))
			goto err;
	}

	if (apol_str_append(&text, &text_sz, "\n"))
		goto err;

	return text;

err:
	free(text);
	free(tmp);
	return NULL;
}

static char *generate_common_only_proof_text(const char *domain, net_state_t *state)
{
	char *text = NULL, *tmp = NULL;
	size_t text_sz = 0, i;
	uint32_t attempt = 0;
	name_perm_t *np = NULL;

	if (apol_str_append(&text, &text_sz, "Domain has incomplete network access.\n\tDomain has no protocol specific permissions only the following:"))
		goto err;

	if (apol_str_append(&text, &text_sz, "\n\tsock_file permissions:"))
		goto err;
	attempt = state->perms & RULE_TCP_SOCK_FILE;
	asprintf(&tmp, "allow %s self : sock_file { ", domain);
	if (attempt) {
		if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
			goto err;
		if (apol_str_append(&text, &text_sz, tmp))
			goto err;
		if (attempt & PERM_SELF_SOCK_FILE_READ) {
			if (apol_str_append(&text, &text_sz, "read "))
				goto err;
		}
		if (attempt & PERM_SELF_SOCK_FILE_WRITE) {
			if (apol_str_append(&text, &text_sz, "write "))
				goto err;
		}
		if (attempt & PERM_SELF_SOCK_FILE_GETATTR) {
			if (apol_str_append(&text, &text_sz, "getattr "))
				goto err;
		}
		if (apol_str_append(&text, &text_sz, "};"))
			goto err;
	}
	free(tmp);
	tmp = NULL;

	if (apol_str_append(&text, &text_sz, "\n\tassociation permissions:"))
		goto err;
	for (i = 0; i < apol_vector_get_size(state->assocs); i++) {
		np = apol_vector_get_element(state->assocs, i);
		attempt = state->perms & RULE_TCP_ASSOC;
		asprintf(&tmp, "allow %s %s : association { ", domain, np->name);
		if (attempt) {
			if (apol_str_append(&text, &text_sz, "\n\t\tHas: "))
				goto err;
			if (apol_str_append(&text, &text_sz, tmp))
				goto err;
			if (attempt & PERM_ASSOC_SEND) {
				if (apol_str_append(&text, &text_sz, "sendto "))
					goto err;
			}
			if (attempt & PERM_ASSOC_RECV) {
				if (apol_str_append(&text, &text_sz, "recvfrom "))
					goto err;
			}
			if (apol_str_append(&text, &text_sz, "};"))
				goto err;
		}
		free(tmp);
		tmp = NULL;
	}

	if (apol_str_append(&text, &text_sz, "\n"))
		goto err;

	return text;

err:
	free(text);
	free(tmp);
	return NULL;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. This function allocates the result
 * structure and fills in all relavant item and proof data. 
 * Return Values:
 *  -1 System error
 *   0 The module "succeeded"	- no negative results found
 *   1 The module "failed" 		- some negative results found */
int inc_net_access_run(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL, *tmp_item = NULL;
	sechk_proof_t *proof = NULL;
	sechk_result_t *net_domain_res = NULL;
	sechk_name_value_t *dep = NULL;
	sechk_mod_fn_t run_fn = NULL;
	size_t i = 0, j = 0;
	int error = 0;
	apol_avrule_query_t *avrule_query = NULL;
	apol_vector_t *avrule_vector = NULL, *net_domain_vector = NULL;
	qpol_type_t *net_domain = NULL, *tmp_type = NULL;
	char *net_domain_name = NULL, *perm_name = NULL, *tgt_name = NULL;
	qpol_avrule_t *rule = NULL;
	qpol_iterator_t *iter = NULL;
	net_state_t *state = NULL;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	res = sechk_result_new();
	if (!res) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto inc_net_access_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
	if ( !(res->items = apol_vector_create()) ) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto inc_net_access_run_fail;
	}

	/* run dependencies */
	for (i = 0; i < apol_vector_get_size(mod->dependencies); i++) {
		dep = apol_vector_get_element(mod->dependencies, i);
		run_fn = sechk_lib_get_module_function(dep->value, SECHK_MOD_FN_RUN, mod->parent_lib);
		run_fn(sechk_lib_get_module(dep->value, mod->parent_lib), policy, NULL);
	}

	net_domain_res = sechk_lib_get_module_result("find_net_domains", mod->parent_lib);
	if (!net_domain_res) {
		error = errno;
		ERR(policy, "%s", "Unable to get results for module find_net_domains");
		goto inc_net_access_run_fail;
	}
	net_domain_vector = (apol_vector_t *)net_domain_res->items;

	avrule_query = apol_avrule_query_create();
	if (!avrule_query) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto inc_net_access_run_fail;
	}
	apol_avrule_query_set_rules(policy, avrule_query, QPOL_RULE_ALLOW);

	for (i = 0; i < apol_vector_get_size(net_domain_vector); i++) {
		tmp_item = apol_vector_get_element(net_domain_vector, i);
		net_domain = tmp_item->item;
		qpol_type_get_name(policy->p, net_domain, &net_domain_name);
		state = net_state_create();

		/* find any self sock_file perms */
		apol_avrule_query_set_source(policy, avrule_query, net_domain_name, 1);
		apol_avrule_query_set_target(policy, avrule_query, net_domain_name, 1);
		apol_avrule_query_append_class(policy, avrule_query, NULL);
		apol_avrule_query_append_class(policy, avrule_query, "sock_file");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_perm_iter(policy->p, rule, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void**)(&perm_name));
				if (!strcmp(perm_name, "read")) {
					state->perms |= PERM_SELF_SOCK_FILE_READ;
				} else if (!strcmp(perm_name, "write")) {
					state->perms |= PERM_SELF_SOCK_FILE_WRITE;
				} else if (!strcmp(perm_name, "getattr")) {
					state->perms |= PERM_SELF_SOCK_FILE_GETATTR;
				} /* no general case else */
				free(perm_name);
				perm_name = NULL;
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&avrule_vector, NULL);

		/* find any self tcp_socket perms */
		apol_avrule_query_append_class(policy, avrule_query, NULL);
		apol_avrule_query_append_class(policy, avrule_query, "tcp_socket");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_perm_iter(policy->p, rule, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void**)(&perm_name));
				if (!strcmp(perm_name, "read")) {
					state->perms |= PERM_SELF_TCP_SOC_READ;
				} else if (!strcmp(perm_name, "write")) {
					state->perms |= PERM_SELF_TCP_SOC_WRITE;
				} else if (!strcmp(perm_name, "create")) {
					state->perms |= PERM_SELF_TCP_SOC_CREATE;
				} /* no general case else */
				free(perm_name);
				perm_name = NULL;
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&avrule_vector, NULL);

		/* find any self udp_socket perms */
		apol_avrule_query_append_class(policy, avrule_query, NULL);
		apol_avrule_query_append_class(policy, avrule_query, "udp_socket");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_perm_iter(policy->p, rule, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void**)(&perm_name));
				if (!strcmp(perm_name, "read")) {
					state->perms |= PERM_SELF_UDP_SOC_READ;
				} else if (!strcmp(perm_name, "write")) {
					state->perms |= PERM_SELF_UDP_SOC_WRITE;
				} else if (!strcmp(perm_name, "create")) {
					state->perms |= PERM_SELF_UDP_SOC_CREATE;
				} /* no general case else */
				free(perm_name);
				perm_name = NULL;
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&avrule_vector, NULL);

		/* find any if_t netif perms */
		apol_avrule_query_set_target(policy, avrule_query, NULL, 0);
		apol_avrule_query_append_class(policy, avrule_query, NULL);
		apol_avrule_query_append_class(policy, avrule_query, "netif");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_target_type(policy->p, rule, &tmp_type);
			qpol_type_get_name(policy->p, tmp_type, &tgt_name);
			qpol_avrule_get_perm_iter(policy->p, rule, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void**)(&perm_name));
				if (!strcmp(perm_name, "tcp_send")) {
					state->perms |= PERM_NETIF_TCP_SEND;
					name_perm_vector_add_perm(state->netifs, tgt_name, PERM_NETIF_TCP_SEND);
				} else if (!strcmp(perm_name, "tcp_recv")) {
					state->perms |= PERM_NETIF_TCP_RECV;
					name_perm_vector_add_perm(state->netifs, tgt_name, PERM_NETIF_TCP_RECV);
				} else if (!strcmp(perm_name, "udp_send")) {
					state->perms |= PERM_NETIF_UDP_SEND;
					name_perm_vector_add_perm(state->netifs, tgt_name, PERM_NETIF_UDP_SEND);
				} else if (!strcmp(perm_name, "udp_recv")) {
					state->perms |= PERM_NETIF_UDP_RECV;
					name_perm_vector_add_perm(state->netifs, tgt_name, PERM_NETIF_UDP_RECV);
				} /* no general case else */
				free(perm_name);
				perm_name = NULL;
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&avrule_vector, NULL);

		/* find any node_t node perms */
		apol_avrule_query_append_class(policy, avrule_query, NULL);
		apol_avrule_query_append_class(policy, avrule_query, "node");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_target_type(policy->p, rule, &tmp_type);
			qpol_type_get_name(policy->p, tmp_type, &tgt_name);
			qpol_avrule_get_perm_iter(policy->p, rule, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void**)(&perm_name));
				if (!strcmp(perm_name, "tcp_send")) {
					state->perms |= PERM_NODE_TCP_SEND;
					name_perm_vector_add_perm(state->nodes, tgt_name, PERM_NODE_TCP_SEND);
				} else if (!strcmp(perm_name, "tcp_recv")) {
					state->perms |= PERM_NODE_TCP_RECV;
					name_perm_vector_add_perm(state->nodes, tgt_name, PERM_NODE_TCP_RECV);
				} else if (!strcmp(perm_name, "udp_send")) {
					state->perms |= PERM_NODE_UDP_SEND;
					name_perm_vector_add_perm(state->nodes, tgt_name, PERM_NODE_UDP_SEND);
				} else if (!strcmp(perm_name, "udp_recv")) {
					state->perms |= PERM_NODE_UDP_RECV;
					name_perm_vector_add_perm(state->nodes, tgt_name, PERM_NODE_UDP_RECV);
				} /* no general case else */
				free(perm_name);
				perm_name = NULL;
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&avrule_vector, NULL);

		/* find any port_t tcp_socket perms */
		apol_avrule_query_append_class(policy, avrule_query, NULL);
		apol_avrule_query_append_class(policy, avrule_query, "tcp_socket");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_target_type(policy->p, rule, &tmp_type);
			qpol_type_get_name(policy->p, tmp_type, &tgt_name);
			/* skip self */
			if (!strcmp(net_domain_name, tgt_name))
				continue;
			qpol_avrule_get_perm_iter(policy->p, rule, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void**)(&perm_name));
				if (!strcmp(perm_name, "send_msg")) {
					state->perms |= PERM_PORT_TCP_SEND;
					name_perm_vector_add_perm(state->tcpsocs, tgt_name, PERM_PORT_TCP_SEND);
				} else if (!strcmp(perm_name, "recv_msg")) {
					state->perms |= PERM_PORT_TCP_RECV;
					name_perm_vector_add_perm(state->tcpsocs, tgt_name, PERM_PORT_TCP_RECV);
				} /* no general case else */
				free(perm_name);
				perm_name = NULL;
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&avrule_vector, NULL);

		/* find any port_t udp_socket perms */
		apol_avrule_query_append_class(policy, avrule_query, NULL);
		apol_avrule_query_append_class(policy, avrule_query, "udp_socket");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_target_type(policy->p, rule, &tmp_type);
			qpol_type_get_name(policy->p, tmp_type, &tgt_name);
			/* skip self */
			if (!strcmp(net_domain_name, tgt_name))
				continue;
			qpol_avrule_get_perm_iter(policy->p, rule, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void**)(&perm_name));
				if (!strcmp(perm_name, "send_msg")) {
					state->perms |= PERM_PORT_UDP_SEND;
					name_perm_vector_add_perm(state->udpsocs, tgt_name, PERM_PORT_UDP_SEND);
				} else if (!strcmp(perm_name, "recv_msg")) {
					state->perms |= PERM_PORT_UDP_RECV;
					name_perm_vector_add_perm(state->udpsocs, tgt_name, PERM_PORT_UDP_RECV);
				} /* no general case else */
				free(perm_name);
				perm_name = NULL;
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&avrule_vector, NULL);

		/* find any assoc_t association perms */
		apol_avrule_query_append_class(policy, avrule_query, NULL);
		apol_avrule_query_append_class(policy, avrule_query, "association");
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_target_type(policy->p, rule, &tmp_type);
			qpol_type_get_name(policy->p, tmp_type, &tgt_name);
			qpol_avrule_get_perm_iter(policy->p, rule, &iter);
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				qpol_iterator_get_item(iter, (void**)(&perm_name));
				if (!strcmp(perm_name, "sendto")) {
					state->perms |= PERM_ASSOC_SEND;
					name_perm_vector_add_perm(state->assocs, tgt_name, PERM_ASSOC_SEND);
				} else if (!strcmp(perm_name, "recvfrom")) {
					state->perms |= PERM_ASSOC_RECV;
					name_perm_vector_add_perm(state->assocs, tgt_name, PERM_ASSOC_RECV);
				} /* no general case else */
				free(perm_name);
				perm_name = NULL;
			}
			qpol_iterator_destroy(&iter);
		}
		apol_vector_destroy(&avrule_vector, NULL);

		/* if has tcp perms check for missing ones */
		if ((state->perms & ((~(COMMON_ACCESS_SET))&(TCP_FULL_PERM_SET))) &&
			((state->perms & RULE_TCP_SOCK_FILE) != RULE_TCP_SOCK_FILE ||
			(state->perms & RULE_TCP_SELF_SOC) != RULE_TCP_SELF_SOC ||
			name_perm_vector_has_incomplete_perms(state->netifs, RULE_TCP_NETIF) ||
			name_perm_vector_has_incomplete_perms(state->nodes, RULE_TCP_NODE) ||
			name_perm_vector_has_incomplete_perms(state->tcpsocs, RULE_TCP_PORT) ||
			name_perm_vector_has_incomplete_perms(state->assocs, RULE_TCP_ASSOC))) {
			item = sechk_item_new(NULL);
			if (!item) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			item->item = net_domain;
			item->test_result = 1;
			item->proof = apol_vector_create();
			if (!item->proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof->type = SECHK_ITEM_NONE;
			proof->elem = NULL;
			proof->text = generate_tcp_proof_text(net_domain_name, state);
			//TODO check that it succeeded
			if (apol_vector_append(item->proof, (void*)proof)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof = NULL;
		}
		/* if has udp send perms check for missing perms */
		if ((state->perms & ((~(COMMON_ACCESS_SET|PERM_SELF_UDP_SOC_CREATE))&(UDP_SEND_PERM_SET))) &&
			((state->perms & RULE_UDPs_SOCK_FILE) != RULE_UDPs_SOCK_FILE ||
			(state->perms & RULE_UDPs_SELF_SOC) != RULE_UDPs_SELF_SOC ||
			name_perm_vector_has_incomplete_perms(state->netifs, RULE_UDPs_NETIF) ||
			name_perm_vector_has_incomplete_perms(state->nodes, RULE_UDPs_NODE) ||
			name_perm_vector_has_incomplete_perms(state->udpsocs, RULE_UDPs_PORT) ||
			name_perm_vector_has_incomplete_perms(state->assocs, RULE_UDPs_ASSOC))) {
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto inc_net_access_run_fail;
				}
				item->item = net_domain;
				item->test_result = 1;
				item->proof = apol_vector_create();
				if (!item->proof) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto inc_net_access_run_fail;
				}
			}
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof->type = SECHK_ITEM_NONE;
			proof->elem = NULL;
			proof->text = generate_udp_send_proof_text(net_domain_name, state);
			//TODO check that it succeeded
			if (apol_vector_append(item->proof, (void*)proof)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof = NULL;
		}
		/* if has udp reveive perms check for missing perms*/
		if ((state->perms & ((~(COMMON_ACCESS_SET|PERM_SELF_UDP_SOC_CREATE))&(UDP_RECV_PERM_SET))) &&
			((state->perms & RULE_UDPr_SOCK_FILE) != RULE_UDPr_SOCK_FILE ||
			(state->perms & RULE_UDPr_SELF_SOC) != RULE_UDPr_SELF_SOC ||
			name_perm_vector_has_incomplete_perms(state->netifs, RULE_UDPr_NETIF) ||
			name_perm_vector_has_incomplete_perms(state->nodes, RULE_UDPr_NODE) ||
			name_perm_vector_has_incomplete_perms(state->udpsocs, RULE_UDPr_PORT) ||
			name_perm_vector_has_incomplete_perms(state->assocs, RULE_UDPr_ASSOC))) {
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto inc_net_access_run_fail;
				}
				item->item = net_domain;
				item->test_result = 1;
				item->proof = apol_vector_create();
				if (!item->proof) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto inc_net_access_run_fail;
				}
			}
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof->type = SECHK_ITEM_NONE;
			proof->elem = NULL;
			proof->text = generate_udp_recv_proof_text(net_domain_name, state);
			//TODO check that it succeeded
			if (apol_vector_append(item->proof, (void*)proof)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof = NULL;
		}
		/* if has only common access perms report that */
		if (!(state->perms & (~(COMMON_ACCESS_SET)))) {
			item = sechk_item_new(NULL);
			if (!item) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			item->item = net_domain;
			item->test_result = 1;
			item->proof = apol_vector_create();
			if (!item->proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof->type = SECHK_ITEM_NONE;
			proof->elem = NULL;
			proof->text = generate_common_only_proof_text(net_domain_name, state);
			//TODO check that it succeeded
			if (apol_vector_append(item->proof, (void*)proof)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			proof = NULL;
		}

		if (item) {
			if (apol_vector_append(res->items, (void*)item)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto inc_net_access_run_fail;
			}
			item = NULL;
		}
		net_state_destroy(&state);
	}
	mod->result = res;

	if (apol_vector_get_size(res->items))
		return 1;
	return 0;

inc_net_access_run_fail:
	apol_avrule_query_destroy(&avrule_query);
	apol_vector_destroy(&avrule_vector, NULL);
	qpol_iterator_destroy(&iter);
	free(perm_name);
	net_state_destroy(&state);
	sechk_item_free(item);
	sechk_proof_free(proof);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The print function generates the text and prints the
 * results to stdout. */
int inc_net_access_print(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused))) 
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0, j=0, k=0, l=0, num_items;
	qpol_type_t *type;
	char *type_name;

	if (!mod || !policy){
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i network domains with insufficient permissions.\n", num_items);
	}

	/* Print current permissions then the permissions that are missing */
	if (outformat & SECHK_OUT_PROOF) {  
		printf("\n");
		for (k = 0; k < num_items; k++) {
			item = apol_vector_get_element(mod->result->items, k);
			if (item) {
				type = item->item;
				qpol_type_get_name(policy->p, type, &type_name);
				printf("%s\n", (char*)type_name);
				for (l = 0; l < apol_vector_get_size(item->proof); l++) {
					proof = apol_vector_get_element(item->proof,l);
					if ( proof )
						printf("\t%s\n", proof->text);
				}
			}
		}
		printf("\n");
	}

	i = 0;
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			item  = apol_vector_get_element(mod->result->items, i);
			type = item->item;
			qpol_type_get_name(policy->p, type, &type_name);
			j %= 4;
			printf("%s%s", type_name, (char *)((j && i != num_items - 1)?", ":"\n"));
		}
		printf("\n");
	}

	return 0;
}

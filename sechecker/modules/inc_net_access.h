/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: dwindsor@tresys.com
 *
 */

#ifndef inc_net_access_H
#define inc_net_access_H

#include "sechecker.h"
#include "policy.h"

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

        int CREATE_PERM;
        int READ_PERM;
        int WRITE_PERM;
        int TCP_RECV_PERM;
        int TCP_SEND_PERM;
        int UDP_RECV_PERM;
        int UDP_SEND_PERM;
        int RECV_MSG_PERM;
        int SEND_MSG_PERM;
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

	idx_cache_t idx_cache;
} inc_net_access_data_t;


/* Module functions:
 * Do not change any of these prototypes or you will not be
 * able to run the module in the library
 * (do, however, replace the inc_net_access with the module name)
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. Be sure to choose a unique name
 * for each module and to set the module name prefix inc_net_access everywhere */
int inc_net_access_register(sechk_lib_t *lib);
int inc_net_access_init(sechk_module_t *mod, policy_t *policy);
int inc_net_access_run(sechk_module_t *mod, policy_t *policy);
void inc_net_access_free(sechk_module_t *mod);
int inc_net_access_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *inc_net_access_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
inc_net_access_data_t *inc_net_access_data_new(void);

static void init_net_state(inc_net_access_data_t *net_data);
static void init_idx_cache(idx_cache_t *idx_cache, policy_t *policy);
static int check_perms(const int type_idx, policy_t * policy, sechk_item_t **item, inc_net_access_data_t *net_state);
static bool_t check_type_perms(const int src_idx, const int dst_idx, const int obj_idx, const int perm_idx, policy_t *policy);
static char *build_proof_str(char *src_type, char *dst_type, char *obj_class, char *perms);
static int build_have_perms_proof(const int type_idx, sechk_proof_t **proof, policy_t *policy, idx_cache_t *idx_cache);
static int validate_net_state(const int type_idx, inc_net_access_data_t *net_data, sechk_proof_t **proof, policy_t *policy);
static void check_socket_perms(const int type_idx, policy_t *policy, inc_net_access_data_t *net_state);
static void check_netif_perms(const int type_idx, policy_t *policy, inc_net_access_data_t *net_state);
static void check_port_perms(const int type_idx, policy_t *policy, inc_net_access_data_t *net_state);
static void check_node_perms(const int type_idx, policy_t *policy, inc_net_access_data_t *net_state);

#endif

/**
 * @file netcon-query.c
 *
 * Provides a way for setools to make queries about portcons,
 * netifcons, and nodecons within a policy.  The caller obtains a
 * query object, fills in its parameters, and then runs the query; it
 * obtains a vector of results.  Searches are conjunctive -- all
 * fields of the search query must match for a datum to be added to
 * the results query.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

#include "component-query.h"

struct apol_portcon_query {
        int proto;
        int low, high;
        apol_context_t *context;
	unsigned int flags;
};

struct apol_netifcon_query {
	char *dev;
	apol_context_t *if_context, *msg_context;
	unsigned int if_flags, msg_flags;
};

struct apol_nodecon_query {
        char proto, addr_proto, mask_proto;
        uint32_t addr[4], mask[4];
	apol_context_t *context;
	unsigned int flags;
};

/******************** portcon queries ********************/

int apol_get_portcon_by_query(apol_policy_t *p,
                              apol_portcon_query_t *po,
                              apol_vector_t **v)
{
        sepol_iterator_t *iter;
        int retval = -1, retval2;
        *v = NULL;
        if (sepol_policydb_get_portcon_iter(p->sh, p->p, &iter) < 0) {
                return -1;
        }
        if ((*v = apol_vector_create()) == NULL) {
                ERR(p, "Out of memory!");
                goto cleanup;
        }
        for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
                sepol_portcon_t *portcon;
                if (sepol_iterator_get_item(iter, (void **) &portcon) < 0) {
                        goto cleanup;
                }
                if (po != NULL) {
                        uint16_t low, high;
                        uint8_t proto;
                        sepol_context_struct_t *context;
                        if (sepol_portcon_get_low_port(p->sh, p->p,
                                                       portcon, &low) < 0 ||
                            sepol_portcon_get_high_port(p->sh, p->p,
                                                        portcon, &high) < 0 ||
                            sepol_portcon_get_protocol(p->sh, p->p,
                                                       portcon, &proto) < 0 ||
                            sepol_portcon_get_context(p->sh, p->p,
                                                      portcon, &context) < 0) {
                                goto cleanup;
                        }
                        if ((po->low >= 0 && ((uint16_t) po->low) != low) ||
                            (po->high >= 0 && ((uint16_t) po->high) != high) ||
                            (po->proto >= 0 && ((uint8_t) po->proto) != proto)) {
                                continue;
                        }
			retval2 = apol_compare_context(p, context, po->context, po->flags);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				continue;
			}
                }
                if (apol_vector_append(*v, portcon)) {
                        ERR(p, "Out of memory!");
                        goto cleanup;
                }
        }

        retval = 0;
 cleanup:
        if (retval != 0) {
                apol_vector_destroy(v, NULL);
        }
        sepol_iterator_destroy(&iter);
        return retval;
}

apol_portcon_query_t *apol_portcon_query_create(void)
{
	apol_portcon_query_t *po = calloc(1, sizeof(*po));
	if (po == NULL) {
		return NULL;
	}
	po->proto = po->low = po->high = -1;
	return po;
}

void apol_portcon_query_destroy(apol_portcon_query_t **po)
{
	if (*po != NULL) {
		apol_context_destroy(&((*po)->context));
		free(*po);
		*po = NULL;
	}
}

int apol_portcon_query_set_proto(apol_policy_t *p __attribute__ ((unused)),
				 apol_portcon_query_t *po, int proto)
{
	po->proto = proto;
	return 0;
}

int apol_portcon_query_set_low(apol_policy_t *p __attribute__ ((unused)),
			       apol_portcon_query_t *po, int low)
{
	po->low = low;
	return 0;
}

int apol_portcon_query_set_high(apol_policy_t *p __attribute__ ((unused)),
                                apol_portcon_query_t *po, int high)
{
	po->high = high;
	return 0;
}

int apol_portcon_query_set_context(apol_policy_t *p __attribute__ ((unused)),
				   apol_portcon_query_t *po,
				   apol_context_t *context,
				   unsigned int range_match)
{
	if (po->context != NULL) {
		apol_context_destroy(&po->context);
	}
	po->context = context;
	po->flags = (po->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

/******************** netifcon queries ********************/

int apol_get_netifcon_by_query(apol_policy_t *p,
			       apol_netifcon_query_t *n,
			       apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1, retval2;
	*v = NULL;
	if (sepol_policydb_get_netifcon_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_netifcon_t *netifcon;
		if (sepol_iterator_get_item(iter, (void **) &netifcon) < 0) {
			goto cleanup;
		}
		if (n != NULL) {
			char *name;
			sepol_context_struct_t *ifcon, *msgcon;
			if (sepol_netifcon_get_name(p->sh, p->p, netifcon, &name) < 0 ||
			    sepol_netifcon_get_if_con(p->sh, p->p, netifcon, &ifcon) < 0 ||
			    sepol_netifcon_get_msg_con(p->sh, p->p, netifcon, &msgcon) < 0) {
				goto cleanup;
			}
			retval2 = apol_compare(p, name, n->dev, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				continue;
			}
			retval2 = apol_compare_context(p, ifcon, n->if_context, n->if_flags);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				continue;
			}
			retval2 = apol_compare_context(p, msgcon, n->msg_context, n->msg_flags);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, netifcon)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	return retval;
}

apol_netifcon_query_t *apol_netifcon_query_create(void)
{
	return calloc(1, sizeof(apol_netifcon_query_t));
}

void apol_netifcon_query_destroy(apol_netifcon_query_t **n)
{
	if (*n != NULL) {
		apol_context_destroy(&((*n)->if_context));
		apol_context_destroy(&((*n)->msg_context));
		free(*n);
		*n = NULL;
	}
}

int apol_netifcon_query_set_device(apol_policy_t *p,
				   apol_netifcon_query_t *n, const char *dev)
{
	return apol_query_set(p, &n->dev, NULL, dev);
}


int apol_netifcon_query_set_if_context(apol_policy_t *p __attribute__ ((unused)),
				       apol_netifcon_query_t *n,
				       apol_context_t *context,
				       unsigned int range_match)
{
	if (n->if_context != NULL) {
		apol_context_destroy(&n->if_context);
	}
	n->if_context = context;
	n->if_flags = (n->if_flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

int apol_netifcon_query_set_msg_context(apol_policy_t *p __attribute__ ((unused)),
					apol_netifcon_query_t *n,
					apol_context_t *context,
					unsigned int range_match)
{
	if (n->msg_context != NULL) {
		apol_context_destroy(&n->msg_context);
	}
	n->msg_context = context;
	n->msg_flags = (n->msg_flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

/******************** nodecon queries ********************/

int apol_get_nodecon_by_query(apol_policy_t *p,
			      apol_nodecon_query_t *n,
			      apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1, retval2;
	sepol_nodecon_t *nodecon = NULL;
	*v = NULL;
	if (sepol_policydb_get_nodecon_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, (void **) &nodecon) < 0) {
			goto cleanup;
		}
		if (n != NULL) {
			unsigned char proto, proto_a, proto_m;
			uint32_t *addr, *mask;
			sepol_context_struct_t *con;
			if (sepol_nodecon_get_protocol(p->sh, p->p, nodecon, &proto) < 0 ||
			    sepol_nodecon_get_addr(p->sh, p->p, nodecon, &addr, &proto_a) < 0 ||
			    sepol_nodecon_get_mask(p->sh, p->p, nodecon, &mask, &proto_m) < 0 ||
			    sepol_nodecon_get_context(p->sh, p->p, nodecon, &con) < 0) {
				goto cleanup;
			}
			if (n->proto >= 0 && n->proto != proto) {
				free(nodecon);
				continue;
			}
			if (n->addr_proto >= 0 &&
			    (n->addr_proto != proto_a ||
			     (proto_a == SEPOL_IPV4 && memcmp(n->addr, addr, 1 * sizeof(uint32_t)) != 0) ||
			     (proto_a == SEPOL_IPV6 && memcmp(n->addr, addr, 4 * sizeof(uint32_t)) != 0))) {
				free(nodecon);
				continue;
			}
			if (n->mask_proto >= 0 &&
			    (n->mask_proto != proto_m ||
			     (proto_m == SEPOL_IPV4 && memcmp(n->mask, mask, 1 * sizeof(uint32_t)) != 0) ||
			     (proto_m == SEPOL_IPV6 && memcmp(n->mask, mask, 4 * sizeof(uint32_t)) != 0))) {
				free(nodecon);
				continue;
			}
			retval2 = apol_compare_context(p, con, n->context, n->flags);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				free(nodecon);
				continue;
			}
		}
		if (apol_vector_append(*v, nodecon)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, free);
		free(nodecon);
	}
	sepol_iterator_destroy(&iter);
	return retval;
}

apol_nodecon_query_t *apol_nodecon_query_create(void)
{
	apol_nodecon_query_t *n = calloc(1, sizeof(apol_nodecon_query_t));
	if (n != NULL) {
		n->proto = n->addr_proto = n->mask_proto = -1;
	}
	return n;
}

void apol_nodecon_query_destroy(apol_nodecon_query_t **n)
{
	if (*n != NULL) {
		apol_context_destroy(&((*n)->context));
		free(*n);
		*n = NULL;
	}
}

int apol_nodecon_query_set_proto(apol_policy_t *p,
				 apol_nodecon_query_t *n, int proto)
{
	if (proto == SEPOL_IPV4 || proto == SEPOL_IPV6) {
		n->proto = (char) proto;
	}
	else if (proto < 0) {
		n->proto = -1;
	}
	else {
		ERR(p, "Invalid protocol value %d.", proto);
		return -1;
	}
	return 0;
}

int apol_nodecon_query_set_addr(apol_policy_t *p,
				apol_nodecon_query_t *n,
				uint32_t *addr,
				int proto)
{
	if (addr == NULL) {
		n->addr_proto = -1;
	}
	else {
		if (proto == SEPOL_IPV4) {
			memcpy(n->addr, addr, 1 * sizeof(uint32_t));
		}
		else if (proto == SEPOL_IPV6) {
			memcpy(n->addr, addr, 4 * sizeof(uint32_t));
		}
		else {
			ERR(p, "Invalid protocol value %d.", proto);
			return -1;
		}
		n->addr_proto = (char) proto;
	}
	return 0;
}

int apol_nodecon_query_set_mask(apol_policy_t *p,
				apol_nodecon_query_t *n,
				uint32_t *mask,
				int proto)
{
	if (mask == NULL) {
		n->mask_proto = -1;
	}
	else {
		if (proto == SEPOL_IPV4) {
			memcpy(n->mask, mask, 1 * sizeof(uint32_t));
		}
		else if (proto == SEPOL_IPV6) {
			memcpy(n->mask, mask, 4 * sizeof(uint32_t));
		}
		else {
			ERR(p, "Invalid protocol value %d.", proto);
			return -1;
		}
		n->mask_proto = (char) proto;
	}
	return 0;
}

int apol_nodecon_query_set_context(apol_policy_t *p __attribute__ ((unused)),
				   apol_nodecon_query_t *n,
				   apol_context_t *context,
				   unsigned int range_match)
{
	if (n->context != NULL) {
		apol_context_destroy(&n->context);
	}
	n->context = context;
	n->flags = (n->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

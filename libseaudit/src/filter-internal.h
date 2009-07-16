/**
 *  @file
 *  Protected interface for seaudit filters.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Jeremy Solt jsolt@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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

#ifndef SEAUDIT_FILTER_INTERNAL_H
#define SEAUDIT_FILTER_INTERNAL_H

#include "seaudit_internal.h"

struct seaudit_filter
{
	seaudit_filter_match_e match;
	char *name;
	char *desc;
	bool strict;
	/** model that is watching this filter */
	seaudit_model_t *model;
	/** vector of strings, for source users */
	apol_vector_t *src_users;
	/** vector of strings, for source roles */
	apol_vector_t *src_roles;
	/** vector of strings, for source types */
	apol_vector_t *src_types;
	/** vector of strings, for source mls levels */
	apol_vector_t *src_mls_lvl;
	/** vector of strings, for source mls clearance */
	apol_vector_t *src_mls_clr;
	/** vector of strings, for target users */
	apol_vector_t *tgt_users;
	/** vector of strings, for target roles */
	apol_vector_t *tgt_roles;
	/** vector of strings, for target types */
	apol_vector_t *tgt_types;
	/** vector of strings, for target mls levels */
	apol_vector_t *tgt_mls_lvl;
	/** vector of strings, for target mls clearance */
	apol_vector_t *tgt_mls_clr;
	/** vector of strings, for target object classes */
	apol_vector_t *tgt_classes;
	/** criteria for permissions, glob expression */
	char *perm;
	/** criteria for executable, glob expression */
	char *exe;
	/** criteria for host, glob expression */
	char *host;
	/** criteria for path, glob expression */
	char *path;
	/** inode criterion, as a literal value */
	unsigned long inode;
	/** pid criterion, as a literal value */
	unsigned int pid;
	/** criterion for command, glob expression */
	char *comm;
	/** criterion for IP address, glob expression */
	char *anyaddr;
	/** criterion for local address, glob expression */
	char *laddr;
	/** criterion for foreign address, glob expression */
	char *faddr;
	/** criterion for source address, glob expression */
	char *saddr;
	/** criterion for destination address, glob expression */
	char *daddr;
	/** criterion for any of the ports, exact match */
	int anyport;
	/** criterion for local port, exact match */
	int lport;
	/** criterion for foreign port, exact match */
	int fport;
	/** criterion for source port, exact match */
	int sport;
	/** criterion for destination port, exact match */
	int dport;
	/** criterion for just plain port, exact match */
	int port;
	/** criterion for netif, exact match */
	char *netif;
	/** criterion for IPC key, exact match */
	int key;
	/** criterion for capability, exact match */
	int cap;
	/** criterion for AVC message type */
	seaudit_avc_message_type_e avc_msg_type;
	struct tm *start, *end;
	seaudit_filter_date_match_e date_match;
};

#endif

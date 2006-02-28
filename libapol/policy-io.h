/* Copyright (C) 2001-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com
 */

/* policy-io.c
 *
 * Policy I/O functions */

#ifndef _APOLICY_POLICYIO_H_
#define _APOLICY_POLICYIO_H_

#include "policy.h"

/* LIBAPOL_DEFAULT_POLICY should be defined in the make environment */
#ifndef LIBAPOL_DEFAULT_POLICY
	#define LIBAPOL_DEFAULT_POLICY "/etc/security/selinux/src/policy/policy.conf"
#endif

/* * Return codes for find_default_policy_file() function. */
#define FIND_DEFAULT_SUCCESS 			0
#define GENERAL_ERROR	 			-1
#define BIN_POL_FILE_DOES_NOT_EXIST 		-2
#define SRC_POL_FILE_DOES_NOT_EXIST 		-3
#define BOTH_POL_FILE_DO_NOT_EXIST 		-4
#define POLICY_INSTALL_DIR_DOES_NOT_EXIST	-5
#define INVALID_SEARCH_OPTIONS			-6

int close_policy(policy_t *policy);
int open_policy(const char* filename, policy_t **policy);
int open_partial_policy(const char* filename, unsigned int options, policy_t **policy);
unsigned int validate_policy_options(unsigned int options);
int find_default_policy_file(unsigned int search_opt, char **policy_file_path);
const char* find_default_policy_file_strerr(int err);

#endif   



/******************** new policy reading below ********************/

/**
 * @file policy-io.h
 *
 * Loads a policy, either source or binary policy, from disk.
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

#ifndef _APOL_POLICY_IO_H_
#define _APOL_POLICY_IO_H_

#include <sepol/sepol.h>

/**
 * Attempt to load a binary policy from disk from the given path.
 * Upon success allocate and return a new handle and a new policydb
 * for the loaded policy.
 *
 * @param path Path to the policy to load.
 * @param policy_handle Reference to a newly allocated error reporting
 * handler, or NULL if load failed.
 * @param policy_db Reference to a newly allocated SELinux binary
 * policy, or NULL if load failed.
 *
 * @return 0 on success, non-zero on failure.
 */
extern int apol_open_binary_policy(const char *path,
                                   sepol_handle_t **policy_handle,
                                   sepol_policydb_t **policydb);

/**
 * Deallocate all memory associated with a policy, including the
 * pointers themselves.  Does nothing if the pointer is already NULL.
 *
 * @param policy_handle Handle to destroy if not NULL.
 * @param policydb Policy database to destroy if not NULL.
 */
extern void apol_close_policy(sepol_handle_t *policy_handle,
                              sepol_policydb_t *policydb);

#endif

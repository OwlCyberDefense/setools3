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

#define POL_TYPE_SOURCE 1
#define POL_TYPE_BINARY 2

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

#include "policy.h"

/**
 *  Open a policy file and load it into a newly created apol_policy.
 *  @param path The path of the policy file to open.
 *  @param policy The policy to create from the file.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *policy will be NULL;
 */
extern int apol_policy_open(const char *path, apol_policy_t **policy);

/**
 * Deallocate all memory associated with a policy, and then set it to
 * NULL.  Does nothing if the pointer is already NULL.
 *
 * @param policy Policy to destroy, if not already NULL.
 */
extern void apol_policy_destroy(apol_policy_t **policy);

#endif

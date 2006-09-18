/**
 *  @file genfscon_query.h
 *  Defines the public interface for searching and iterating over genfscon statements.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#ifndef QPOL_OCON_QUERY_H
#define QPOL_OCON_QUERY_H

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

typedef struct qpol_genfscon qpol_genfscon_t;

/**
 *  Get a genfscon statement by file system name and path.
 *  @param policy The policy from which to get the genfscon statement.
 *  @param name The name of the file system.
 *  @param path The path relative to the filesystem mount point.
 *  @param genfscon Pointer in which to store the genfscon statement.
 *  The caller should call free() on this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *genfscon will be NULL.
 */
extern int qpol_policy_get_genfscon_by_name(qpol_policy_t *policy, const char *name, const char *path, qpol_genfscon_t **genfscon);

/**
 *  Get an iterator for the genfscon statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_genfscon_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy() 
 *  to free memory used by this iterator. The caller must also call free()
 *  on items returned by qpol_iterator_get_item() when using this iterator.
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails, 
 *  errno will be set and *iter will be NULL.
 */
extern int qpol_policy_get_genfscon_iter(qpol_policy_t *policy, qpol_iterator_t **iter);

/**
 *  Get the file system name from a gefscon statement.
 *  @param policy The policy associated with the genfscon statement.
 *  @param genfs The genfscon statement from which to get the name.
 *  @param name Pointer to th string in which to store the name.
 *  The caller should not free this string.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
extern int qpol_genfscon_get_name(qpol_policy_t *policy, qpol_genfscon_t *genfs, char **name);

/**
 *  Get the relative path from a gefscon statement.
 *  @param policy The policy associated with the genfscon statement.
 *  @param genfs The genfscon statement from which to get the path.
 *  @param path Pointer to th string in which to store the path.
 *  The caller should not free this string.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *path will be NULL.
 */
extern int qpol_genfscon_get_path(qpol_policy_t *policy, qpol_genfscon_t *genfs, char **path);

/* values from flask do not change */
#define QPOL_CLASS_ALL        0
#define QPOL_CLASS_BLK_FILE  11
#define QPOL_CLASS_CHR_FILE  10
#define QPOL_CLASS_DIR        7
#define QPOL_CLASS_FIFO_FILE 13
#define QPOL_CLASS_FILE       6
#define QPOL_CLASS_LNK_FILE   9
#define QPOL_CLASS_SOCK_FILE 12

/**
 *  Get the object class from a genfscon statement.
 *  @param policy The policy associated with the genfscon statement.
 *  @param genfs The genfscon statement from which to get the path.
 *  @param class Pointer in which to store the integer code for the
 *  object class. See QPOL_CLASS_* defines above for values.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *class will be 0.
 */
extern int qpol_genfscon_get_class(qpol_policy_t *policy, qpol_genfscon_t *genfs, uint32_t *class);

/**
 *  Get the context from a path component of a genfscon statement.
 *  @param policy The policy associated with the genfscon statement.
 *  @param genfscon The genfscon statement from which to get 
 *  the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
extern int qpol_genfscon_get_context(qpol_policy_t *policy, qpol_genfscon_t *genfscon, qpol_context_t **context);

#endif /* QPOL_OCON_QUERY_H */ 

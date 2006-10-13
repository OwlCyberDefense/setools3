/**
 * @file fshash.h
 *
 * Public interface for a hash table containing bind mounts and their
 * file contexts.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2006 Tresys Technology, LLC
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

#ifndef SEFS_FS_HASH_H
#define SEFS_FS_HASH_H

typedef struct sefs_hash sefs_hash_t;

/**
 * Allocate and return a new hash table with the given number of
 * buckets.
 *
 * @param size Number of buckets for the new hash table.
 *
 * @return A newly allocated hash table, or NULL upon error.  The
 * caller must call sefs_hash_destroy() upon the returned value
 * afterwards.
 */
extern sefs_hash_t *sefs_hash_new(int size);

/**
 * Insert a key into the hash table, if it is not already there.  This
 * function will make a duplicate of the supplied string.
 *
 * @param hashtab Hash table to which insert.
 * @param key Key to insert.
 *
 * @return 0 on success, < 0 on error.
 */
extern int sefs_hash_insert(sefs_hash_t *hashtab, const char *key);

/**
 * Search for a particular key within the hash table.
 *
 * @param hashtab Hash table to search.
 * @param key Key within the hash table to find.
 *
 * @return 1 if the key was found, 0 if not, < 0 on error.
 */
extern int sefs_hash_find(sefs_hash_t *hashtab, const char *key);

/**
 * Deallocate all space associated with the given hash table,
 * including the pointer itself.
 *
 * @return hashtab Hash table to destroy.
 */
extern void sefs_hash_destroy(sefs_hash_t *hashtab);

#endif /* SEFS_FS_HASH_H */

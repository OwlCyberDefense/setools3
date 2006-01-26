/* Copyright (C) 2005-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* fshash.h
 *
 * hash fcns for bind mount hashing 
 *
 */
#ifndef _FS_HASH_H
#define _FS_HASH_H

typedef struct sefs_hash_node {
	struct sefs_hash_node *next;
	char *key;               
} sefs_hash_node_t;

typedef struct sefs_hash {
	sefs_hash_node_t **table;
	int size;
} sefs_hash_t;

sefs_hash_t *sefs_hash_new(int size);
int sefs_hash_insert(sefs_hash_t *hashtab, const char *key);
int sefs_hash_find(sefs_hash_t *hashtab, const char *key);
void sefs_hash_destroy(sefs_hash_t *hashtab);

#endif /* _FS_HASH_H */

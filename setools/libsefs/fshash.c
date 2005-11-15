/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* fshash.c
 *
 * hash fcns for bind mount hashing 
 *
 */
#include "fshash.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
  Initialize the hash
 */
sefs_hash_t *sefs_hash_new(int size)
{
	sefs_hash_t *hashtab = NULL;

	if (size < 1)
		return NULL;

	hashtab = (sefs_hash_t *)calloc(1, sizeof(sefs_hash_t));
	if (!hashtab) {
		fprintf(stderr, "Out of memory\n");
		return NULL;
	}
	hashtab->table = (sefs_hash_node_t **)calloc(size, sizeof(sefs_hash_node_t *));
	if (!hashtab) {
		fprintf(stderr, "Out of memory\n");
		return NULL;
	}
	hashtab->size = size;
	return hashtab;
}

/* Hash function, this can be optimized */
unsigned sefs_hash(const char *s, int size)
{
	unsigned hashval;

	for (hashval = 0; *s != '\0'; s++)
		hashval = *s + 31 *hashval;
	return hashval % size;
}

/* search the hash for key 
   return -1 on no hash
   return 1 on find
   return 0 on no find
*/
int sefs_hash_find(sefs_hash_t *hashtab, const char *key)
{
	sefs_hash_node_t *np;

	if (hashtab == NULL || !(hashtab->table))
		return -1;
	for (np = hashtab->table[sefs_hash(key, hashtab->size)]; np != NULL; np = np->next)
		if (strcmp(key, np->key) == 0)
			return 1;
	return 0;
}

/* insert the key into the hash */
int sefs_hash_insert(sefs_hash_t *hashtab, const char *key)
{
	sefs_hash_node_t *np;
 	unsigned hashval;
	
	if (hashtab == NULL)
		return -1;

	if (!sefs_hash_find(hashtab, (char*)key)) {
		np = (sefs_hash_node_t*)calloc(1, sizeof(sefs_hash_node_t));
		if (np == NULL || (np->key = strdup(key)) == NULL) {
			/* if np is already null free will not cause problems */
			free(np);
			return -1;
		}
		hashval = sefs_hash(key, hashtab->size);
		np->next = hashtab->table[hashval];
		hashtab->table[hashval] = np;	
	} else {
		printf("Error: Duplicate key attempted to be inserted\n");
		return -1;
	}
	return 0;
}

/* clear out the data and destroy the hash  */
void sefs_hash_destroy(sefs_hash_t *hashtab)
{
	sefs_hash_node_t *curr,*next;
	int i;

	if (hashtab == NULL)
		return;

	for (i = 0; i < hashtab->size; i++) {
		curr = hashtab->table[i];
		if (curr) {
			while (curr) {
				free(curr->key);
				next = curr->next;
				free(curr);
				curr = next;
			}
		}	
	}
	free(hashtab->table);
	free(hashtab);
}


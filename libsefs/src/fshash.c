/**
 * @file fshash.c
 *
 * Implementation of a simple hash table (really a string array).
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

#include <config.h>

#include <sefs/fshash.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct sefs_hash_node
{
	struct sefs_hash_node *next;
	char *key;
} sefs_hash_node_t;

struct sefs_hash
{
	sefs_hash_node_t **table;
	int size;
};

sefs_hash_t *sefs_hash_new(int size)
{
	sefs_hash_t *hashtab = NULL;

	if (size < 1)
		return NULL;

	hashtab = (sefs_hash_t *) calloc(1, sizeof(sefs_hash_t));
	if (!hashtab) {
		fprintf(stderr, "Out of memory\n");
		return NULL;
	}
	hashtab->table = (sefs_hash_node_t **) calloc(size, sizeof(sefs_hash_node_t *));
	if (!hashtab) {
		fprintf(stderr, "Out of memory\n");
		return NULL;
	}
	hashtab->size = size;
	return hashtab;
}

/* Hash function, this can be optimized */
static unsigned sefs_hash(const char *s, int size)
{
	unsigned hashval;

	for (hashval = 0; *s != '\0'; s++)
		hashval = *s + 31 * hashval;
	return hashval % size;
}

int sefs_hash_find(sefs_hash_t * hashtab, const char *key)
{
	sefs_hash_node_t *np;

	if (hashtab == NULL || !(hashtab->table))
		return -1;
	for (np = hashtab->table[sefs_hash(key, hashtab->size)]; np != NULL; np = np->next)
		if (strcmp(key, np->key) == 0)
			return 1;
	return 0;
}

int sefs_hash_insert(sefs_hash_t * hashtab, const char *key)
{
	sefs_hash_node_t *np;
	unsigned hashval;

	if (hashtab == NULL)
		return -1;

	if (!sefs_hash_find(hashtab, (char *)key)) {
		np = (sefs_hash_node_t *) calloc(1, sizeof(sefs_hash_node_t));
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

void sefs_hash_destroy(sefs_hash_t * hashtab)
{
	sefs_hash_node_t *curr, *next;
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

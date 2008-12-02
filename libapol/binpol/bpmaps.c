/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * Binary policy maps for tranlating between binary
 * policy files and apol structures.
 *
 * Also contains our ebitmap unique functions
 */
#include <asm/types.h>
#include <assert.h>
#include <stdlib.h>
#include "ebitmap.h"
#include "bpmaps.h"

static void free_bmap_emap(ebitmap_t *e, int num)
{
	int i;
	if(e == NULL )
		return;
	assert (num > 0);
	for(i = 0; i < num; i++) {
		ebitmap_destroy(&e[i]);
	}
	free(e);
	return;	
}

static void free_bmap_perm_map(ap_permission_bmap_t *pmap, int num)
{
	int i;
	if(pmap == NULL)
		return;
	assert(num > 0);
	for(i = 0; i < num; i++) {
		if(pmap[i].map != NULL) {
			assert(pmap[i].num > 0);
			free(pmap[i].map);
		}
	}
	free(pmap);
	return;
}

ap_bmaps_t *ap_new_bmaps(void)
{
	ap_bmaps_t *t;
	
	t = (ap_bmaps_t *)malloc(sizeof(ap_bmaps_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	
	memset(t, 0, sizeof(ap_bmaps_t));
	
	return t;
}

int ap_add_alias_bmap(char *alias, __u32 val, ap_bmaps_t *bm)
{
	ap_alias_bmap_t *t;
	
	if(alias == NULL || bm == NULL)
		return -1;
		
	assert(val <= bm->t_num);
	
	t = (ap_alias_bmap_t *)malloc(sizeof(ap_alias_bmap_t));
	if(t == NULL) {
		fprintf(stdout, "out of memory\n");
		return -1;
	}
	t->name = alias;
	t->val = val;
	t->next = NULL;
	
	if(bm->alias_map == NULL) 
		bm->alias_map = bm->alias_map_last = t;
	else {
		bm->alias_map_last->next = t;
		bm->alias_map_last = t;
	}

	return 0;	
}

int ap_free_alias_bmap(ap_bmaps_t *bm)
{
	ap_alias_bmap_t *a, *tmp;
	for(a = bm->alias_map; a != NULL;) {
		if(a->name != NULL)
			free(a->name);
		tmp = a->next;
		free(a);
		a = tmp;
		
	}

	return 0;

}

void ap_free_bmaps(ap_bmaps_t *bm)
{
	if(bm == NULL)
		return;

	if(bm->cp_map != NULL)
		free(bm->cp_map);
	if(bm->rev_cp_map != NULL)
		free(bm->rev_cp_map);
	free_bmap_perm_map(bm->cp_perm_map, bm->cp_num);
	if(bm->cls_map != NULL)
		free(bm->cls_map);
	free_bmap_perm_map(bm->cls_perm_map, bm->cls_num);
	if(bm->r_map != NULL)
		free(bm->r_map);
	if(bm->r_emap != NULL) 
		free_bmap_emap(bm->r_emap, bm->r_num);
	if(bm->t_map != NULL)
		free(bm->t_map);
	if(bm->alias_map != NULL)
		ap_free_alias_bmap(bm);
	if(bm->u_map != NULL)
		free(bm->u_map);
	if(bm->bool_map != NULL)
		free(bm->bool_map); 
		
	free(bm);
	return;
}


/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 * Modified by: don.patterson@tresys.com - added perm map loading from mls functions.
 */

/* perm-map.c
 *
 * Permission mapping routines for libapol.  These maps assoicate all
 * object class permissions with read, write, read&write, and none access.
 * These maps are used, for example, by an information flow analysis.
 */

#include "perm-map.h"
#include "policy.h"
#include "util.h"
#include <stdio.h>
#include <assert.h>
#include <time.h>

void free_perm_mapping(classes_perm_map_t *p)
{
	int i;
	if(p == NULL)
		return;
	for(i = 0; i < p->num_classes; i++) {
		if(p->maps[i].cls_name != NULL)
			free(p->maps[i].cls_name);
		free(p->maps[i].perm_maps);
	}
	free(p->maps);
	free(p);
	return;
}

/* initializes map using opened policy, and allocates spaced for defined object classes.
 * Does create link list for each object class with the permissions */
classes_perm_map_t *new_perm_mapping(policy_t *policy)
{
	classes_perm_map_t *t = NULL;
	int i, j, num, k;
	
	if(policy == NULL)
		return NULL;

	t = (classes_perm_map_t *)malloc(sizeof(classes_perm_map_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	memset(t, 0, sizeof(classes_perm_map_t));
	t->num_classes = policy->num_obj_classes;
	
	t->maps = (class_perm_map_t *)malloc(sizeof(class_perm_map_t) * t->num_classes);
	if(t->maps == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	/* initialize with all the classes from provided policy */
	for(i = 0 ; i < t->num_classes; i++) {
		num = num_of_class_perms(i, policy);
		if(num < 0) {
			fprintf(stderr, "unexpected error determining number of permissions for class: %d\n", i);
			return NULL;
		}
		t->maps[i].num_perms = num;
		t->maps[i].perm_maps = (perm_map_t *)malloc(sizeof(perm_map_t) * num);
		if(t->maps[i].perm_maps == NULL) {
			fprintf(stderr, "out of memory");
			return NULL;
		} 
		/* initialize with all the permissions for each class from provided policy */
		for(j = 0; j < num; j++) {
			if(j < policy->obj_classes[i].num_u_perms) {
				t->maps[i].perm_maps[j].perm_idx = policy->obj_classes[i].u_perms[j];
				t->maps[i].perm_maps[j].map = PERMMAP_UNMAPPED;
				t->maps[i].perm_maps[j].weight = (char) PERMMAP_MIN_WEIGHT;
			} 
			else {
				/* If we're here, then there must be common perms */
				assert(is_valid_common_perm_idx(policy->obj_classes[i].common_perms, policy));
				for(k = 0; k < policy->common_perms[policy->obj_classes[i].common_perms].num_perms; k++) {
					assert(k < policy->common_perms[policy->obj_classes[i].common_perms].num_perms);
					t->maps[i].perm_maps[j+k].perm_idx = policy->common_perms[policy->obj_classes[i].common_perms].perms[k];
					t->maps[i].perm_maps[j+k].map = PERMMAP_UNMAPPED;
					t->maps[i].perm_maps[j+k].weight = (char) PERMMAP_MIN_WEIGHT;
				} 
				assert(k == policy->common_perms[policy->obj_classes[i].common_perms].num_perms);
				assert(j == policy->obj_classes[i].num_u_perms);
				assert(j+k == num);
				break;	/* this is the loop exit spot for objects with common perms */
			} 
		} 
		t->maps[i].mapped = FALSE;
		t->maps[i].cls_idx = i;
		t->maps[i].cls_name = NULL; 
	}
	return t;
}

static unsigned char pmap_unmapped_perms(class_perm_map_t *obj_map)
{
	int i;
	if(obj_map == NULL)
		return TRUE;
	for(i = 0; i < obj_map->num_perms; i++) {
		if(obj_map->perm_maps[i].map == PERMMAP_UNMAPPED)
			return TRUE;
	} 
	return FALSE;
} 

static unsigned char pmap_convert_map_char(char mapid)
{
	switch(mapid) {
	case 'r':
	case 'R':	return PERMMAP_READ;
	case 'w':
	case 'W':	return PERMMAP_WRITE;
	case 'b':
	case 'B':	return PERMMAP_BOTH;
	case 'n':
	case 'N':	return PERMMAP_NONE;
	default:	fprintf(stderr, "Warning: invalid map character (%c); permission will be unmapped\n", mapid);
			return PERMMAP_UNMAPPED;
	} 
} 

static int pmap_get_map_idx_from_cls(class_perm_map_t *obj_map, int perm_idx, policy_t *policy)
{
	int i;
	if(obj_map == NULL || policy == NULL || !is_valid_perm_idx(perm_idx, policy))
		return -1;
		
	for(i = 0; i < obj_map->num_perms; i++) {
		if(obj_map->perm_maps[i].perm_idx == perm_idx) 
			return i;
	}
	return -1;
} 

/* special case: if obj_idx < 0, then just read the object and throw away the information;
 * this allows us to reposition the file pointer to the next object record */
static unsigned int load_perm_map_for_object(int obj_idx, int num_perms, classes_perm_map_t *map, policy_t *policy, FILE *fp)
{
	unsigned int ret = PERMMAP_RET_SUCCESS;
	class_perm_map_t *obj_map = NULL;
	unsigned char skip;
	int i, idx, pm_idx, perm_weight;
	char line[LINE_SZ], perm[LINE_SZ], mapid;
	char *line_ptr = NULL;
	
	fpos_t fpos;
	
	if(obj_idx < 0) {
		if(fp == NULL)
			return PERMMAP_RET_ERROR;
		skip = TRUE;
	} else if (num_perms == 0) {
		ret |= PERMMAP_RET_UNMAPPED_PERM;
		fprintf(stderr, "Warning: some permission were unmapped for object index %d (%s)\n", obj_idx, policy->obj_classes[obj_idx].name);
		map->mapped = TRUE;
		return ret;
	} else {
		if(map == NULL || policy == NULL || fp == NULL || obj_idx < 0 || obj_idx >= map->num_classes) 
			return PERMMAP_RET_ERROR;
	
		obj_map = &(map->maps[obj_idx]);
		if(obj_map->mapped != PERMMAP_UNMAPPED)
			ret |= PERMMAP_RET_OBJ_REMMAPPED;
		skip = FALSE;
	} 
	i = 0;
	while((fgetpos(fp, &fpos) == 0) && fgets(line, LINE_SZ, fp) != NULL) {
		line_ptr = &line[0];
		if (trim_string(&line_ptr) != 0)
			return PERMMAP_RET_ERROR;
		if(line_ptr[0] == '#' || str_is_only_white_space(line_ptr))
			continue;
		if(sscanf(line_ptr, "%s %c %d", perm, &mapid, &perm_weight) != 3) {
			/* This may be a perm map file w/o perm weigthing. */
			if(sscanf(line_ptr, "%s %c", perm, &mapid) != 2) {
				fprintf(stderr, "Error loading object map object index %d (%s); invalid format for line: \"%s\"\n", obj_idx, policy->obj_classes[obj_idx].name, line_ptr);
				return PERMMAP_RET_ERROR;
			}
			perm_weight = PERMMAP_MAX_WEIGHT;
		}

		i++;
		if(strcmp(perm, "class") == 0) {
			/* means we've moved onto next object or encountered EOF, before we've read num_perms # of permissions*/
			fprintf(stderr, "Warning: there were less than %d permissions recorded for object index %d\n", num_perms, obj_idx);
			/* reset the file position so that the next obj class will be read correctly */
			fsetpos(fp, &fpos);
			ret |= PERMMAP_RET_UNMAPPED_PERM;
			i = num_perms; /* fake out the EOF check */
			break;
		} 
		if(skip) {
			if(i == num_perms) {
				break;
			} else {
				continue;
			}
		} 
		idx = get_perm_idx(perm, policy);
		if(idx < 0) {
			fprintf(stderr, "Warning: unknown permission (%s) for object class %s; it will be ignored\n", perm, policy->obj_classes[obj_idx].name);
			ret |= PERMMAP_RET_UNKNOWN_PERM;
			if(i == num_perms)
				break;
			else
				continue;
		}
		pm_idx = pmap_get_map_idx_from_cls(obj_map, idx, policy);
		if(pm_idx < 0) {
			fprintf(stderr, "Warning: permission (%s) is not defined for object class %s (idx: %d); it will be ignored\n", perm, policy->obj_classes[obj_idx].name, obj_idx);
			ret |= PERMMAP_RET_UNKNOWN_PERM;
			if(i == num_perms)
				break;
			else
				continue;		} 
		obj_map->perm_maps[pm_idx].map = pmap_convert_map_char(mapid);
	
		/* weight must be between 1 - 10 to be valid. If less than 1, set to minimum; if greater than 10, set to max */
		if (perm_weight > 10) {
			fprintf(stderr, "Weight value (%d) for permission %s in object %s is invalid. Setting to default maximum weight.\n", perm_weight, perm, policy->obj_classes[obj_idx].name);
			perm_weight = 10;
		} else if (perm_weight < 0) {
			fprintf(stderr, "Weight value (%d) for permission %s in object %s is invalid. Setting to default minimum weight.\n", perm_weight, perm, policy->obj_classes[obj_idx].name);
			perm_weight = 1;
		}
		
		/* By default, if there is no weight provided, weight will be set to PERMMAP_MAX_WEIGHT. */
		obj_map->perm_maps[pm_idx].weight = (char) perm_weight;
			
		if(i == num_perms)
			break;
	}	
	
	if(i < num_perms && feof(fp)) {
		/* means we've encountered EOF, before we've read num_perms # of permissions for the last object class */
		fprintf(stderr, "Warning: there were less than %d permissions recorded for object index %d\n", num_perms, obj_idx);
		ret |= PERMMAP_RET_UNMAPPED_PERM;
	}
	
	if(!skip && pmap_unmapped_perms(obj_map)) {
		fprintf(stderr, "Warning: some permission were unmapped for object index %d (%s)\n", obj_idx, policy->obj_classes[obj_idx].name);
		ret |= PERMMAP_RET_UNMAPPED_PERM;
	} 		
	/* map will be null if this is an unknown object class */
	if (!skip)
		map->mapped = TRUE;
	return ret;
}


unsigned int load_perm_mappings(classes_perm_map_t **map, policy_t *policy, FILE *fp)
{
	unsigned int ret = PERMMAP_RET_SUCCESS;
	int num_objs, num_perms, i = 0, idx;
	char line[LINE_SZ], id[LINE_SZ];
	char *line_ptr = NULL;
	
	if(policy == NULL || map == NULL) {
		return PERMMAP_RET_ERROR;
	}
	rewind(fp);
	*map = new_perm_mapping(policy);
	if(*map == NULL) {
		fprintf(stderr, "Error: getting new perm mapping\n");
		return PERMMAP_RET_ERROR;
	}
	
	while(fgets(line, LINE_SZ, fp) != NULL) {
		line_ptr = &line[0];
		if (trim_string(&line_ptr) != 0)
			return PERMMAP_RET_ERROR;
		
		if(line_ptr[0] == '#' || (sscanf(line_ptr, "%d", &num_objs) != 1 ))  
			continue;
		else {
			for(i = 0; i < num_objs; i++) {
				while(fgets(line, LINE_SZ, fp) != NULL) {
					line_ptr = &line[0];
					if (trim_string(&line_ptr) != 0)
						return PERMMAP_RET_ERROR;
					if(line_ptr[0] == '#' || (sscanf(line_ptr, "%*s %s %d", id, &num_perms) != 2 ))  
						continue;
					else {
						idx = get_obj_class_idx(id, policy);
						if(idx < 0) {
							/* An undefined object; need to add it */
							fprintf(stderr, "Warning: object (%s) unknown to current policy; will be ignored\n", id);
							ret |= PERMMAP_RET_UNKNOWN_OBJ;
							/* skip to next record */
							load_perm_map_for_object(-1, 0, NULL, NULL, fp);
							continue;
						}
						else {
							/* in new_perm_mapping() the array of objects
							 * was ordered in exactly the same ordeer as the
							 * opened policy, so we can just directly use
							 * the idx */
							(*map)->maps[idx].cls_idx = idx;
							ret |= load_perm_map_for_object(idx,num_perms,*map, policy, fp);
							if(ret & PERMMAP_RET_ERROR) {
								fprintf(stderr, "Error: trying to load perm map for: %s (%d)\n",id,idx);
								return PERMMAP_RET_ERROR;
							}
						}	
					}
				}
				return ret; /* success case */
			}
		}
	}
	fprintf(stderr, "Error: getting number of objects\n");
	return PERMMAP_RET_ERROR;
}

unsigned int load_policy_perm_mappings(policy_t *policy, FILE *fp)
{
	if(policy == NULL)
		return PERMMAP_RET_ERROR;

	if(policy->pmap != NULL) {
		free_perm_mapping(policy->pmap);
		policy->pmap = NULL;
	}
			
	return load_perm_mappings(&policy->pmap, policy, fp);
}

/* write out the perm map file 
 * fp presumed to be opened for write access
 */
int write_perm_map_file(classes_perm_map_t *map, policy_t *policy, FILE *outfile)
{
	int rt;
	time_t ltime;
	int i, j;
	class_perm_map_t *cls;
	
	if(policy == NULL || outfile == NULL || map == NULL)
		return -1;
	
	time(&ltime);
	rt = fprintf(outfile, "# Auto-generated by apol on %s\n", ctime(&ltime));	
	if(rt < 0)
		return -1;
	rt = fprintf(outfile, "#\n# permission map file\n\n");
	if(rt < 0)
		return -1;	
	rt = fprintf(outfile, "\nNumber of classes (mapped?: %s):\n", (map->mapped ? "yes" : "no"));
	if(rt < 0)
		return -1;
	rt = fprintf(outfile, "%d\n", map->num_classes);
	if(rt < 0)
		return -1;
		
	for(i = 0; i < map->num_classes; i++) {
		cls = &map->maps[i];
		rt = fprintf(outfile, "\nclass %s %d\n", policy->obj_classes[cls->cls_idx].name, cls->num_perms);
		if(rt < 0)
			return -1;
		
		for(j = 0; j < cls->num_perms; j++) {
			if(cls->perm_maps[j].map & PERMMAP_UNMAPPED) {
				fprintf(outfile, "#%18s     ", policy->perms[cls->perm_maps[j].perm_idx]);
			} else {
				fprintf(outfile, "%18s     ", policy->perms[cls->perm_maps[j].perm_idx]);
			}
			if((cls->perm_maps[j].map & PERMMAP_BOTH) == PERMMAP_BOTH) {
				fprintf(outfile, "b  ");
			}  else {
				switch(cls->perm_maps[j].map & (PERMMAP_READ|PERMMAP_WRITE|PERMMAP_NONE|PERMMAP_UNMAPPED)) {
				case PERMMAP_READ: 	fprintf(outfile, "r  ");
							break;
				case PERMMAP_WRITE: 	fprintf(outfile, "w  ");
							break;	
				case PERMMAP_NONE: 	fprintf(outfile, "n  ");
							break;
				case PERMMAP_UNMAPPED: 	fprintf(outfile, "u  ");
							break;	
				default:		fprintf(outfile, "?  ");
				} 
			} 
			fprintf(outfile, "%10d\n", cls->perm_maps[j].weight);
		} 
	} 
	
	return 0;
}

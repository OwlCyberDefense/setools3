/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* perm-map.h
 *
 * Permission mapping routines for libapol.  These maps assoicated all
 * object class permissions with read, write, read&write, and none access.
 * These maps are used, for example, by an information flow analysis.
 */


#ifndef _APOLICY_PERMMAP_H_
#define _APOLICY_PERMMAP_H_
#include "policy.h"
#include <stdio.h>

#define PERMMAP_MAX_WEIGHT 10
#define PERMMAP_MIN_WEIGHT 1

/* Permission maps: For each object class we need to map all permisions
 * to either read and/or write, or non similar as is done for the MLS stuff.
 * This allows us to determine information flow.  These mappings will be
 * loadable so that users can re-map them as they see fit. 
 *
 * Map for a given permission */
typedef struct perm_map {
	int		perm_idx; 	/* index into policy_t->perms */
#define PERMMAP_UNMAPPED	0x00	/* defined object/perm, but no map */
#define	PERMMAP_READ		0x01
#define PERMMAP_WRITE		0x02
#define PERMMAP_BOTH		(PERMMAP_READ | PERMMAP_WRITE)
#define PERMMAP_NONE		0x10	
#define PERMMAP_UNDEFINED	0x20	/* undefined obj/perm, but with map */
	unsigned char	map;
	char 		weight;		/* the weight (importance) of this perm. (least) 1 - 10 (most); */
} perm_map_t;

/* There is one class_perm_map_t per object class. */
typedef struct class_perm_map {
	unsigned char	mapped;		/* mask */
	int		num_perms;
	int		cls_idx;	/* idx of class from policy */
	char		*cls_name;	/* only used if idx is not valid (< 0); i.e., for unknown objects*/
					/* cls_name currently unused*/
	perm_map_t	*perm_maps; 	/* array; one each for each perm bit defined */
} class_perm_map_t;

/* the entire map */
typedef struct classes_perm_map {
	unsigned char		mapped;		/* boolean */
	int			num_classes;	/* # of obj classes with a map (sz of maps array) */
	class_perm_map_t 	*maps;		/* array */
} classes_perm_map_t;

/* returns masks used for load_perm_mappings() */ 
#define	PERMMAP_RET_SUCCESS		0x00000000	/*success, no warnings nor errors */
#define PERMMAP_RET_ERROR		0x10000000	/*general error, see stderr, no useful data returned */
#define PERMMAP_RET_UNMAPPED_PERM	0x00000001	/*initialized, but some perms unmapped*/
#define PERMMAP_RET_UNMAPPED_OBJ	0x00000002	/*initialized, but some objects unmapped*/
#define	PERMMAP_RET_UNKNOWN_PERM	0x00000004	/*initialized, but 1+ perms associated with incorrect or unknown (and ignored)*/
#define PERMMAP_RET_UNKNOWN_OBJ		0x00000008	/*initialized, but some object from file unknown and ignored*/
#define PERMMAP_RET_OBJ_REMMAPPED	0x00000010	/*object was mapped more than once*/
#define PERMMAP_RET_WARNINGS		(PERMMAP_RET_UNMAPPED_PERM|PERMMAP_RET_UNMAPPED_OBJ|PERMMAP_RET_UNKNOWN_PERM|PERMMAP_RET_UNKNOWN_OBJ|PERMMAP_RET_OBJ_REMMAPPED)

/* prototypes */
void free_perm_mapping(classes_perm_map_t *p);
classes_perm_map_t * new_perm_mapping(policy_t *policy);
unsigned int load_perm_mappings(classes_perm_map_t **map, policy_t *policy, FILE *fp);
unsigned int load_policy_perm_mappings(policy_t *policy, FILE *fp);
int write_perm_map_file(classes_perm_map_t *map, policy_t *policy, FILE *outfile);

#endif /*_APOLICY_PERMMAP_H_*/

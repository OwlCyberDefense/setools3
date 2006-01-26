/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * Binary policy maps for tranlating between binary
 * policy files and apol structures
 */

#ifndef _APOLICY_BINPOL_BMAPS_H_
#define _APOLICY_BINPOL_BMAPS_H_

#include <asm/types.h>
#include "ebitmap.h"
#include "../policy.h"

/* Our temporary mapping structures */

typedef struct aliases_map {
	char	*name;	
	__u32	val;
	struct aliases_map *next;
} ap_alias_bmap_t;

typedef struct permisson_map {
	int	num;
	int	*map;
} ap_permission_bmap_t;

/* As of version 20 binary policies, there are three policy components
   which may have aliases:  types, sensitivities, and categories. */
#define AP_ALIAS_TYPE 0
#define AP_ALIAS_SENS 1
#define AP_ALIAS_CATS 2

typedef struct bpmaps {
	int	*cp_map;	/* common permission (from val to idx) */
	__u32 	*rev_cp_map;	/* common permission (from idx to val) */
	ap_permission_bmap_t *cp_perm_map; /* from val to idx */
	int	cp_num;
	int	*cls_map;	/* object classes */
	ap_permission_bmap_t *cls_perm_map; /* from val to idx */
	int	cls_num;
	int	*r_map;		/* roles */
	ebitmap_t *r_emap;	/* role entended bit maps */
	int	r_num;
	int	*t_map;		/* types */
	int	t_num;
	int	*a_map;		/* attribs */
	int	a_num;
	ap_alias_bmap_t *alias_map[3];	/* aliases (top) */
	ap_alias_bmap_t *alias_map_last[3]; /* (bottom) */
	int	*u_map;		/* users */
	int	u_num;
	int	*bool_map;	/* conditional booleans */
	int	bool_num;
	int	sens_num;	/* number of MLS sensitivies */
	int	*sens_map;
        int	cats_num;	/* number of MLS categories */
} ap_bmaps_t;

ap_bmaps_t *ap_new_bmaps(void);
void ap_free_bmaps(ap_bmaps_t *bm);
int ap_add_alias_bmap(char *alias, __u32 val, ap_bmaps_t *bm, int which);

#endif

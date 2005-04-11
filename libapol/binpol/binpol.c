/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * Support from binary policies in libapol
 *
 * Some of the functions are borrowed, in part or in full, 
 * from the checkpolicy source code 
 */

#include <sys/types.h>
#include <asm/types.h>
#include "binpol.h"
#include "fbuf.h"
#include "borrowed.h"
#include "bpmaps.h"
#include "ebitmap.h"
#include "../policy.h"
#include "../policy-io.h"
#include "../util.h"
#include <assert.h>
#include <stdio.h>

#define INTERNAL_ASSERTION assert(fp != NULL && policy != NULL && bm != NULL && fb != NULL && !(fb->buf == NULL && fb->sz > 0));

/* macro to ensure that values from disk are within range of map (sum tabs) size on disk */
#define binpol_validate_val(val, hi) ((val <= hi && val > 0) ? 1 : 0)

#define binpol_get_bit(mask, bit) ((mask >> bit) & 01)

#define binpol_enabled(mask) ((mask & AVTAB_ENABLED) == AVTAB_ENABLED)

__u32 mls_config = 0;

static int skip_ebitmap(ap_fbuf_t *fb, FILE *fp)
{
	__u32 *buf, count, highbit, i;
	
	assert(fb != NULL && fp != NULL);
	buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp); 
	if(buf == NULL)	return fb->err; 
	/* [0] mapsize
	 * [1] highbit
	 * [2] count */
	count = le32_to_cpu(buf[2]);
	highbit = le32_to_cpu(buf[1]);
	
	if(!highbit)
		return 0; /* finished */
	
	for (i = 0; i < count; i++) {
		if(fseek(fp, sizeof(__u32), SEEK_CUR) != 0)  
			 return -3;
		if(fseek(fp, sizeof(__u64), SEEK_CUR) != 0)  
			 return -3;
	}
	return 0;
}

static int skip_mls_range(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf, nlvl;

	INTERNAL_ASSERTION

	buf = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf == NULL) return fb->err;
	
	nlvl = le32_to_cpu(buf[0]);
	if (fseek(fp, sizeof(__u32)*nlvl, SEEK_CUR))
		return -3;
	if (skip_ebitmap(fb,fp))
		return -3;
	if (nlvl > 1){
		if (skip_ebitmap(fb,fp))
			return -3;
	} 
	return 0;
}

static int skip_mls_level(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf;
	
	INTERNAL_ASSERTION

	buf = ap_read_fbuf(fb, sizeof(__u32), fp);
	if (buf == NULL)
		return fb->err;

	return skip_ebitmap(fb,fp);
}

/*********************************************************************
 * NOTE: for all these internal load functions, the following define
 *       indicates success but with the item not saved in the policy,
 *       so therefore any returned index cannot be used.  Since we
 *       MUST use a negative number for this indicator, you MUST
 *       check this value first before doing the typical rt < 0 check.
 **********************************************************************/
#define	LOAD_SUCCESS_NO_SAVE	-99


/* returns index of permission added, or LOAD_SUCCESS_NO_SAVE is not being saved */
static int load_perm(ap_fbuf_t *fb, FILE *fp, __u32 *val, unsigned int opts, policy_t *policy)
{
	char *kbuf;
	size_t len;
	__u32 *buf;
	int idx;
	bool_t keep = FALSE;
	
	if (opts & POLOPT_PERMS)
		keep = TRUE;
	
	buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
	if(buf == NULL)	return fb->err;
	/* buf[0] len of key
	 * buf[1] value */
	len = le32_to_cpu(buf[0]);
	*val = le32_to_cpu(buf[1]);

	/* perm name */
	kbuf = ap_read_fbuf(fb, len, fp);
	if(kbuf == NULL) return fb->err;
	/* add_perm() copies the string, so we don't need to allocate separate
	 * storage here */
	kbuf[len] = '\0';
	
	if(keep) {
		idx = add_perm(kbuf, policy);
		if(idx < 0) {
			assert(FALSE); /* debug aide */
			return -4;
		}
		return idx;
	}
	else
		return LOAD_SUCCESS_NO_SAVE;
}

/* is_cp:	indicates whether container entity is common perm (TRUE) or class
 * cval:	binary's policy value for container
 * cidx:	libapol index for container
 * cp_cidx:	if class (is_cp==FALSE), idx of class's common perm; -1 means no common perm (ignored for common perm)
 * nel:		# of permissions to read
 */
static int load_perms(ap_fbuf_t *fb, FILE *fp, bool_t is_cp, __u32 cval, int cidx, int cp_idx, size_t nel, 
			ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	int i, idx, rt = 0;
	bool_t keep = FALSE;
	ap_permission_bmap_t *pmap = NULL;
	__u32 val, num_cp = 0;
	
	if(nel == 0)
		return 0;
	
	if (opts & POLOPT_PERMS)
		keep = TRUE;
	
	if(keep) {
		if(is_cp) {
			assert(cval <= bm->cp_num);
			assert(is_valid_common_perm_idx(cidx, policy));
			pmap = &bm->cp_perm_map[cval-1];
		} 
		else { /* class */
			assert(cval <= bm->cls_num);
			assert(is_valid_obj_class_idx(cidx, policy));
			pmap = &bm->cls_perm_map[cval-1];
			if(cp_idx >= 0) {
				assert(is_valid_common_perm_idx(cp_idx, policy));
				num_cp = num_common_perm_perms(cp_idx, policy);
			}
		}
		assert(pmap != NULL);
	
		/* perm mapping space for classes is pre-allocated, if common perm we need to do here */
		if(is_cp) {
			pmap->map = (int *)malloc(sizeof(int) * (nel+num_cp));
			if(pmap->map == NULL)
				return -1;
			pmap->num = nel;
		}
		assert(pmap->map != NULL); /* double check for class case */
	}

	for (i = 0; i < nel; i++) {
		idx = load_perm(fb, fp, &val, opts, policy);
		if(idx < 0 && idx != LOAD_SUCCESS_NO_SAVE ) {
			return idx;
		}
		
		if(keep) {
			if(is_cp) {
				rt = add_perm_to_common(cidx, idx, policy);
			}
			else {
				rt = add_perm_to_class(cidx, idx, policy);
			}
			if(rt != 0) {
				assert(FALSE); /* debug aide */
				return -4;
			}
			/* 'idx' is perm idx, map it; 'i' is the place of the perm in the container map
			 * 'val' is its value in the binary policy */

			assert(val <= nel+num_cp);
			pmap->map[val-1] = idx;
		}
	}
	return 0;
}

static int load_common_perm(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	size_t len, nel;
	unsigned char *kbuf, *key;
	__u32 *buf, val;
	int rt, idx = -1;
	bool_t keep = FALSE;
	
	INTERNAL_ASSERTION
	
	if (opts & POLOPT_PERMS)
		keep = TRUE;
	
	buf = ap_read_fbuf(fb, sizeof(__u32)*4, fp); 
	if(buf == NULL)	return fb->err;
	/* buf[0] is len of key (name) string
	 * buf[1] is value 
	 * buf[2] is num of permissions
	 * buf[3] is nel */
	len = le32_to_cpu(buf[0]);
	nel = le32_to_cpu(buf[3]);
	val = le32_to_cpu(buf[1]);
	if(!binpol_validate_val(val, bm->cp_num)) {
		assert(FALSE); /* debug aide */
		return -7;
	}
	
	/* common perm name */
	kbuf = ap_read_fbuf(fb, len, fp);
	if(kbuf == NULL) return fb->err;
	
	if(keep) {
		key = (char *)malloc(len + 1);
		if(key == NULL) return -1;
		memcpy(key, kbuf, len);
		key[len] = '\0';
		idx = add_common_perm(key, policy);
		if(idx < 0) {/* -2 idx means the common perm was already in policy; an error */
			free(key);
			assert(FALSE); /* debug aide */
			return -4;
		}
		bm->cp_map[val-1] = idx;
		bm->rev_cp_map[idx] = val;
	}
	/* load perms */
	rt = load_perms(fb, fp, TRUE, val, idx, -1, nel, bm, opts, policy);
	if(rt < 0)
		return rt;
	
	if(keep)
		return idx;
	else
		return LOAD_SUCCESS_NO_SAVE;
}

static int load_class(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	size_t len, len2, nel, ncons, nexpr, nvaltrans;
	unsigned char *kbuf, *key, *cbuf;
	__u32 *buf, expr_type, val, i, j, num_cp = 0, cp_val = -1;
	int rt, idx = -1, idx2 = -1;		/* idx2 (common perm idx) must ne init'd to -1 for load_perms */
	bool_t keep = FALSE;
	
	INTERNAL_ASSERTION
	
	if (opts & POLOPT_CLASSES)
		keep = TRUE;
	
	buf = ap_read_fbuf(fb, sizeof(__u32)*6, fp); 
	if(buf == NULL)	return fb->err;
	/* buf[0] len of key (name) string
	 * buf[1] len2 of common key (name) string
	 * buf[2] value 
	 * buf[3] num unique permissions (ignore)
	 * buf[4] nel
	 * buf[5] num constraints (ignore constraints) */	
	
	len = le32_to_cpu(buf[0]);
	len2 = le32_to_cpu(buf[1]);
	val = le32_to_cpu(buf[2]);
	if(!binpol_validate_val(val, bm->cls_num)) {
		assert(FALSE); /* debug aide */
		return -7;
	}
	nel = le32_to_cpu(buf[4]);
	ncons = le32_to_cpu(buf[5]);
	
	/* class name */
	kbuf = ap_read_fbuf(fb, len, fp);
	if(kbuf == NULL) return fb->err;
	
	if(keep) {
		key = (char *)malloc(len + 1);
		if(key == NULL) return -1;
		memcpy(key, kbuf, len);
		key[len] = '\0';
		idx = add_class(key, policy);
		if(idx < 0) {
			free(key);
			assert(FALSE); /* debug aide */
			return -4;
		}
		bm->cls_map[val-1] = idx;
	}
	
	/* common permission */
	if(len2) {
		cbuf = ap_read_fbuf(fb, len2, fp);
		if(cbuf == NULL) return fb->err;
		if(keep) {
			cbuf[len2] = '\0';
			idx2 = get_common_perm_idx(cbuf, policy);
			if(idx2 < 0) {
				assert(FALSE); /* debug aide */
				return -4;
			}
			cp_val = bm->rev_cp_map[idx2];
			rt = add_common_perm_to_class(idx, idx2, policy);
			if( rt <  0) {
				assert(FALSE); /* debug aide */
				return -4;
			}
			num_cp = num_common_perm_perms(idx2, policy);
		}
	}
	/* we allocate mapping space for class perms here, since we might have a common perm
	 * that we need to map before loading the unique perms */
	if(keep) { 
		bm->cls_perm_map[val-1].map = (int *)malloc(sizeof(int) * (num_cp+nel));
		if(bm->cls_perm_map[val-1].map == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;				
		}
		bm->cls_perm_map[val-1].num = num_cp+nel;
	}
	/* map common perms (if any) */
	if(num_cp > 0 ) {
		for(i = 0; i < num_cp; i++) {
			bm->cls_perm_map[val-1].map[i] = bm->cp_perm_map[cp_val-1].map[i];
		}
	}

	/* unique permissions */
	rt = load_perms(fb, fp, FALSE, val, idx, idx2, nel, bm, opts, policy);
	if(rt < 0)
		return rt;
	
	/* ignore constraints */
	for(i = 0; i < ncons; i++) {
		buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
		if(buf == NULL)	return fb->err;
		/* buf[0] permissions (ignore)
		 * buf[1] num expressions */
		nexpr = le32_to_cpu(buf[1]);
		/* all expressions */
		for (j = 0; j < nexpr; j++) {
			buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp); 
			if(buf == NULL)	return fb->err; 
			/* buf[0] expression type
			 * buf[1] attr (ignore)
			 * buf[2] op (ignore) */
			expr_type = le32_to_cpu(buf[0]);
			switch (expr_type) {
			case CEXPR_NOT:
			case CEXPR_AND:
			case CEXPR_OR:
			case CEXPR_ATTR:
				/* all of these expression types do not have additional data 
				 * in file so we can ignore them */
				break;
			case CEXPR_NAMES:
				rt = skip_ebitmap(fb, fp);
				if(rt != 0)
					return rt;
				break;
			default:
				return -3;
				break;
			}
		}
	}
	
	if (policy->version >= POL_VER_19) {
		buf = ap_read_fbuf(fb, sizeof(__u32), fp);
		nvaltrans = le32_to_cpu(buf[0]);
		/* ignore validatetrans constraints */
		for(i = 0; i < nvaltrans; i++) {
			buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
			if(buf == NULL)	return fb->err;
			/* buf[0] permissions (ignore)
			 * buf[1] num expressions */
			nexpr = le32_to_cpu(buf[1]);
			/* all expressions */
			for (j = 0; j < nexpr; j++) {
				buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp); 
				if(buf == NULL)	return fb->err; 
				/* buf[0] expression type
				 * buf[1] attr (ignore)
				 * buf[2] op (ignore) */
				expr_type = le32_to_cpu(buf[0]);
				switch (expr_type) {
				case CEXPR_NOT:
				case CEXPR_AND:
				case CEXPR_OR:
				case CEXPR_ATTR:
					/* all of these expression types do not have additional data 
					 * in file so we can ignore them */
					break;
				case CEXPR_NAMES:
					rt = skip_ebitmap(fb, fp);
					if(rt != 0)
						return rt;
					break;
				default:
					return -3;
					break;
				}
			}
		}
	}

	if(keep)
		return idx;
	else
		return LOAD_SUCCESS_NO_SAVE;
}

static int load_role(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf, val;
	size_t len;
	unsigned char *kbuf, *key;
	int idx = -1, rt; 
	bool_t keep = FALSE;

	INTERNAL_ASSERTION

	if (opts & POLOPT_ROLES)
		keep = TRUE;

	buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
	if(buf == NULL)	return fb->err;
	/* buf[0] len of key (name) string
	 * buf[1] value */
	len = le32_to_cpu(buf[0]);
	val = le32_to_cpu(buf[1]);
	if(!binpol_validate_val(val, bm->r_num)) {
		assert(FALSE); /* debug aide */
		return -7;
	}
		
	/* role name */
	kbuf = ap_read_fbuf(fb, len, fp);
	if(kbuf == NULL) return fb->err;
	if(keep) {
		key = (char *)malloc(len + 1);
		if(key == NULL) return -1;
		memcpy(key, kbuf, len);
		key[len] = '\0';
		
		idx = add_role(key, policy);
		if(idx < 0) {
			free(key);
			assert(FALSE); /* debug aide */
			return -4;
		}
		assert(val <= bm->r_num);
		bm->r_map[val-1] = idx;
	}
	
	/* TODO: ignore role domainance for now */
	rt = skip_ebitmap(fb, fp);
	if(rt != 0)
		return rt;
	
	/* process types (store bitmaps for now we'll process them after 
	 * loading the type) */
	rt = ebitmap_read(fb, &bm->r_emap[val-1], fp);
	if(rt != 0)
		return rt;

	if(keep)
		return idx;
	else
		return LOAD_SUCCESS_NO_SAVE;
}

static int load_type(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf, val;
	size_t len;
	unsigned char *kbuf, *key;
	int idx = 0, rt;
	bool_t keep = FALSE, primary;
	
	INTERNAL_ASSERTION

	if (opts & POLOPT_TYPES) {
		keep = TRUE;
	}

	buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp); 
	if(buf == NULL) return fb->err;
	/* buf[0] len of key (name) string
	 * buf[1] value 
	 * buf[2] primary name boolean (determine whether this primary name or alias) */
	len = le32_to_cpu(buf[0]);
	val = le32_to_cpu(buf[1]);
	primary = le32_to_cpu(buf[2]);
	if(!binpol_validate_val(val, bm->t_num)) {
		assert(FALSE); /* debug aide */
		return -7;
	}
	
	/* type name */
	kbuf = ap_read_fbuf(fb, len, fp);
	if(kbuf == NULL) return fb->err;
	if(keep) {
		key = (char *)malloc(len + 1);
		if(key == NULL) return -1;
		memcpy(key, kbuf, len);
		key[len] = '\0';
		if(!primary) { /* alias */
			/* we store away aliases for now and post-process them
			 * in order to add them to our type structure.  This is
			 * required because the val of an alias may not yet be
			 * valid type reference for our structure */
			rt = ap_add_alias_bmap(key, val, bm);
			if(rt < 0) {
				free(key);
				return -1;
			}	
		}
		else { /* primary type name */
			idx = add_type(key, policy);
			if(idx < 0) {
				free(key); 
				assert(FALSE); /* debug aide */
				return -4;
			}
			bm->t_map[val-1] = idx;
		}
	}	

	if(keep)
		return idx;
	else
		return LOAD_SUCCESS_NO_SAVE;
}

static int load_user(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf, val;
	size_t len;
	unsigned char *kbuf, *key;
	bool_t keep = FALSE;
	int i, rt, idx = -1;
	ebitmap_t e;

	INTERNAL_ASSERTION
	
	if (opts & POLOPT_USERS)
		keep = TRUE;

	buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
	/* buf[0] len of key (name) string
	 * buf[1] value */
	len = le32_to_cpu(buf[0]);
	val = le32_to_cpu(buf[1]);

	/* user name */
	kbuf = ap_read_fbuf(fb, len, fp);
	if(kbuf == NULL) return fb->err;
	if(keep) {
		key = (char *)malloc(len + 1);
		if(key == NULL) return -1;
		memcpy(key, kbuf, len);
		key[len] = '\0';
		
		idx = add_user(key, policy);
		if(idx < 0) {
			free(key);
			assert(FALSE); /* debug aide */
			return -4;
		}
		bm->u_map[val-1] = idx;
	}	

	/* process the user's roles  */
	rt = ebitmap_read(fb, &e, fp);
	if(rt != 0)
		return rt;
	if(keep) {
		for(i = 0; i < e.highbit; i++) {
			if(ebitmap_get_bit(&e, i)) {
				rt = add_role_to_user(bm->r_map[i], idx, policy);
				if(rt < 0) {
					assert(FALSE); /* debug aide */
					ebitmap_destroy(&e);
					return -4;
				}
			}
		}
	}
	
	ebitmap_destroy(&e);
	
	if (policy->version >= POL_VER_19) {
		skip_mls_range(fb, fp, bm, opts, policy);
		skip_mls_level(fb, fp, bm, opts, policy);
	}

	return 0;
}

static int load_bool(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 len, *buf, val;
	bool_t keep = FALSE, state;
	unsigned char *key;
	int idx;
	
	INTERNAL_ASSERTION
	
	if (opts & POLOPT_COND_BOOLS)
		keep = TRUE;
	
	buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp); 
	if(buf == NULL)	return fb->err;
	/* buf[0] val (binary pol index)
	 * buf[1] state (boolean default value)
	 * buf[2] len of name string
	 */
	val = le32_to_cpu(buf[0]);
	state = le32_to_cpu(buf[1]); 
	len = le32_to_cpu(buf[2]);
	
	/* bool name */
	buf = ap_read_fbuf(fb, len, fp);
	if(buf == NULL) return fb->err;
	if(keep) {
		key = (char *)malloc(len + 1);
		if(key == NULL) return -1;
		memcpy(key, buf, len);
		key[len] = '\0';
		
		idx = add_cond_bool(key, state, policy);
		if (idx < 0) {
			free(key);
			assert(FALSE);
			return -4;
		}
		assert(val <= bm->bool_num);
		bm->bool_map[val-1] = idx;
	}
			 
	if(keep)
		return idx;
	else
		return LOAD_SUCCESS_NO_SAVE;
}

static int load_role_trans(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf, nel, rval, tval, new_rval, i;
	int ridx, tidx, new_ridx;
	bool_t keep = FALSE;
	
	INTERNAL_ASSERTION
	
	if (opts & POLOPT_ROLE_RULES)
		keep = TRUE;
	
	buf = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf == NULL) return fb->err;
	nel = le32_to_cpu(buf[0]);
	if (!nel) 
		return 0; /* no role trans rules*/

	for (i = 0; i < nel; i++) {
		buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp);
		if(buf == NULL) return fb->err;
		if(!keep)
			continue;
		rval = le32_to_cpu(buf[0]);
		if(rval > bm->r_num) {
			assert(FALSE);
			return -4;
		}
		tval = le32_to_cpu(buf[1]);
		if(tval > bm->t_num){
			assert(FALSE);
			return -4;
		}
		new_rval = le32_to_cpu(buf[2]);
		if(new_rval > bm->r_num){
			assert(FALSE);
			return -4;
		}
		ridx = bm->r_map[rval-1];
		assert(is_valid_role_idx(ridx, policy));
		tidx = bm->t_map[tval-1];
		assert(is_valid_type_idx(tidx, policy));
		new_ridx = bm->r_map[new_rval-1];
		assert(is_valid_role_idx(new_ridx, policy));
		
		/* TODO: We don't presently have a nice "add_role_trans()" function, and 
		 * the parser handles this in a much more general manner than we need to here
		 * in a binary policy (becuase, we don't have multiple roles and types).
		 *
		 * So we will just explictly handle the insertion here (tho at some point
		 * it would be better to fix this lack of abstraction).
		 */
		{
			rt_item_t *rule; /* new rule ptr */
			ta_item_t *role = NULL, *type = NULL;
			
			/* make sure list is large enough */
			if(policy->num_role_trans >= policy->list_sz[POL_LIST_ROLE_TRANS]) {
				/* grow the dynamic array */
				rt_item_t *ptr;		
				ptr = (rt_item_t *)realloc(policy->role_trans, 
					(LIST_SZ+policy->list_sz[POL_LIST_ROLE_TRANS]) * sizeof(rt_item_t));
				if(ptr == NULL) {
					fprintf(stderr, "out of memory\n");
					return -1;
				}
				policy->role_trans = ptr;
				policy->list_sz[POL_LIST_ROLE_TRANS] += LIST_SZ;
			}	
			rule = &(policy->role_trans[policy->num_role_trans]);
			memset(rule, 0, sizeof(rt_item_t));
			
			/* handle source role */
			role = (ta_item_t *)malloc(sizeof(ta_item_t));
			if(role == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			role->type = IDX_ROLE;
			role->idx = ridx;
			if(insert_ta_item(role, &(rule->src_roles)) != 0) {
				assert(FALSE);
				return -4;
			}
			
			/* handle target type */
			type = (ta_item_t *)malloc(sizeof(ta_item_t));
			if(type == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			type->type = IDX_TYPE;
			type->idx = tidx;
			if(insert_ta_item(type, &(rule->tgt_types)) != 0) {
				assert(FALSE); /* debug aide */
				return -4;
			}
			
			/* handle new role */
			rule->trans_role.idx = new_ridx;
			rule->trans_role.type = IDX_ROLE;
						
			/* update policy counters */
			(policy->num_role_trans)++;	
			(policy->rule_cnt[RULE_ROLE_TRANS])++;
		}
	}
	return 0;
}


static int load_role_allow(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf, nel, rval, new_rval, i;
	int ridx, new_ridx;
	bool_t keep = FALSE;
	
	INTERNAL_ASSERTION
	
	if (opts & POLOPT_ROLE_RULES)
		keep = TRUE;
	
	buf = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf == NULL) return fb->err;
	nel = le32_to_cpu(buf[0]);
	if (!nel) 
		return 0; /* no role allow rules*/

	for (i = 0; i < nel; i++) {
		buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp);
		if(buf == NULL) return fb->err;
		if(!keep) 
			continue;
		rval = le32_to_cpu(buf[0]);
		if(rval > bm->r_num) {
			assert(FALSE);
			return -4;
		}
		new_rval = le32_to_cpu(buf[1]);
		if(new_rval > bm->r_num){
			assert(FALSE);
			return -4;
		}
		ridx = bm->r_map[rval-1];
		assert(is_valid_role_idx(ridx, policy));
		new_ridx = bm->r_map[new_rval-1];
		assert(is_valid_role_idx(new_ridx, policy));
		
		/* TODO: As with role_trans, we don't presently have a nice "add_role_trans()" function.
		 * The source parser handles this in a much more general manner than we need to here
		 * in a binary policy (becuase, we don't have multiple source roles).
		 *
		 * So we will just explictly handle the insertion here.
		 */
		{
			ta_item_t *role = NULL;
			role_allow_t *rule = NULL;
			
			/* make sure list is large enough */
			if(policy->num_role_allow >= policy->list_sz[POL_LIST_ROLE_ALLOW]) {
				/* grow the dynamic array */
				role_allow_t * ptr;		
				ptr = (role_allow_t *)realloc(policy->role_allow, (LIST_SZ+policy->list_sz[POL_LIST_ROLE_ALLOW]) * sizeof(role_allow_t));
				if(ptr == NULL) {
					fprintf(stderr, "out of memory\n");
					return -1;
				}
				policy->role_allow = ptr;
				policy->list_sz[POL_LIST_ROLE_ALLOW] += LIST_SZ;
			}	
			rule = &(policy->role_allow[policy->num_role_allow]);
			memset(rule, 0, sizeof(role_allow_t));
			
			/* handle source role */
			role = (ta_item_t *)malloc(sizeof(ta_item_t));
			if(role == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			role->type = IDX_ROLE;
			role->idx = ridx;
			if(insert_ta_item(role, &(rule->src_roles)) != 0) {
				assert(FALSE);
				return -4;
			}
			
			/* handle target role*/
			role = (ta_item_t *)malloc(sizeof(ta_item_t));
			if(role == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			role->type = IDX_ROLE;
			role->idx = new_ridx;
			if(insert_ta_item(role, &(rule->tgt_roles)) != 0) {
				assert(FALSE);
				return -4;
			}
						
			/* update policy counters */
			(policy->num_role_allow)++;	
			(policy->rule_cnt[RULE_ROLE_ALLOW])++;
		}
	}
	return 0;
}


static int load_initial_sids(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	
	INTERNAL_ASSERTION
	
	if (opts & POLOPT_INITIAL_SIDS)
		keep = TRUE;
	
	/* TODO: Currently initial SIDs not supported for binary policies.  The reason is that
	 * the binary policy does not store the symbolic name of initial sids, yet apol
	 * assumes these names and keys off of them.  Thus until we resolve this issue, initial
	 * sids will not be supported */
	return 0;
}

static int insert_into_new_tt_item(int rule_type, int src, int tgt, int cls, int def_type,
		bool_t enabled, policy_t *policy)
{
	ta_item_t *titem;
	tt_item_t *item;
	int rule_idx;
	
	if (rule_type == RULE_TE_TRANS || rule_type == RULE_TE_MEMBER || rule_type == RULE_TE_CHANGE) {
		item = add_new_tt_rule(rule_type, policy);
		rule_idx = policy->num_te_trans - 1;
	}
	else {
		assert(FALSE); /* debug aide */
		return -4;
	}
	
	/* source */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stdout, "out of memory\n");
		return -1;
	}
	titem->type = IDX_TYPE;
	titem->idx = src;
	if(insert_ta_item(titem, &(item->src_types)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	
	/* target */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stdout, "out of memory\n");
		return -1;
	}
	titem->type = IDX_TYPE;
	titem->idx = tgt;
	if(insert_ta_item(titem, &(item->tgt_types)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	/* class */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stdout, "out of memory\n");
		return -1;
	}
	titem->type = IDX_OBJ_CLASS;
	titem->idx = cls;
	if(insert_ta_item(titem, &(item->classes)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	
	/* new default type */
	item->dflt_type.type = IDX_TYPE;
	item->dflt_type.idx = def_type;
	
	/* state */
	item->enabled = enabled;
	
	/* return the rule index for new rule */
	return rule_idx;
}



static int insert_into_new_av_item(int rule_type, int src, int tgt, int cls, 
		bool_t enabled, policy_t *policy)
{
	ta_item_t *titem;
	av_item_t *item;
	int rule_idx;
	
	if (rule_type == RULE_TE_ALLOW || rule_type == RULE_NEVERALLOW) {
		item = add_new_av_rule(rule_type, policy);
		rule_idx = policy->num_av_access - 1;
	}
	else if(rule_type == RULE_DONTAUDIT || rule_type == RULE_AUDITDENY || rule_type == RULE_AUDITALLOW) {
		item = add_new_av_rule(rule_type, policy);
		rule_idx = policy->num_av_audit - 1;
	}
	else {
		assert(FALSE); /* debug aide */
		return -4;
	}
	
	/* source */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stdout, "out of memory\n");
		return -1;
	}
	titem->type = IDX_TYPE;
	titem->idx = src;
	if(insert_ta_item(titem, &(item->src_types)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	
	/* target */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stdout, "out of memory\n");
		return -1;
	}
	titem->type = IDX_TYPE;
	titem->idx = tgt;
	if(insert_ta_item(titem, &(item->tgt_types)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	/* class */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stdout, "out of memory\n");
		return -1;
	}
	titem->type = IDX_OBJ_CLASS;
	titem->idx = cls;
	if(insert_ta_item(titem, &(item->classes)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	
	/* state */
	item->enabled = enabled;
	
	/* return the rule index for new rule */
	return rule_idx;
}

static ta_item_t *decode_perm_mask(__u32 mask, int clsidx, __u32 cval, ap_bmaps_t *bm, policy_t *policy)
{
	ta_item_t *top = NULL, *t;
	int i, idx, n, rt;
	
	assert(policy != NULL && is_valid_obj_class_idx(clsidx, policy));
	assert(mask);
	assert(bm != NULL);
	assert(cval <= bm->cls_num);
	
	/* get number of perms for object class */
	n = get_num_perms_for_obj_class(clsidx, policy);
	for(i = 0; i < n; i++) {
		if(binpol_get_bit(mask, i)) {
			assert( i < bm->cls_perm_map[cval-1].num);
			idx = bm->cls_perm_map[cval-1].map[i];
			assert(is_valid_perm_idx(idx, policy));
			
			t = (ta_item_t *)malloc(sizeof(ta_item_t));
			if(t == NULL) {
				fprintf(stderr, "out of memory \n");
				return NULL;
			}
			t->type = IDX_PERM;
			t->idx = idx;
			t->next = NULL;
			rt = insert_ta_item(t, &top);
			if(rt != 0)
				return NULL;
		}
	}
	
	assert(top != NULL);
	return top;
}



static int add_binary_avrule(avtab_datum_t *avdatum, avtab_key_t *avkey, ap_bmaps_t *bm, 
			unsigned int opts, cond_rule_list_t *r_list, policy_t *policy)
{
	int src = 0, tgt = 0, cls = 0, dflt = 0, rule_idx = 0; /* indicies from bmaps */
	ta_item_t *perms;
	bool_t is_cond, enabled;
		
	assert(avdatum != NULL && avkey != NULL && bm != NULL && policy != NULL);
	src = tgt = cls = dflt = rule_idx = -1;
	is_cond = (r_list != NULL);
	enabled = (is_cond ? binpol_enabled(avdatum->specified) : TRUE);

	if(avdatum->specified & (AVTAB_AV|AVTAB_TYPE)) {
		
		/* re-map the src, tgr, and class indicies */
		
		if(!binpol_validate_val(avkey->source_type, bm->t_num)) {
			assert(FALSE); /* debug aide */
			return -7;
		}
		if(!binpol_validate_val(avkey->target_type, bm->t_num)) {
			assert(FALSE); /* debug aide */
			return -7;
		}
		if(!binpol_validate_val(avkey->target_class, bm->cls_num)) {
			assert(FALSE); /* debug aide */
			return -7;
		}
		src = bm->t_map[avkey->source_type-1];
		tgt = bm->t_map[avkey->target_type-1];
		cls = bm->cls_map[avkey->target_class-1];
		assert(is_valid_type(policy, src, 1));
		assert(is_valid_type(policy, tgt, 1));
		assert(is_valid_obj_class_idx(cls, policy));
	}

	if (avdatum->specified & AVTAB_AV) {
		
		if(avdatum->specified & AVTAB_ALLOWED) {
			rule_idx = insert_into_new_av_item(RULE_TE_ALLOW, src, tgt, cls, 
					enabled, policy);
			if(rule_idx < 0) return rule_idx;
			if(avtab_allowed(avdatum)) {
				perms = decode_perm_mask(avtab_allowed(avdatum), cls, avkey->target_class, bm, policy);
				assert(perms != NULL);
				policy->av_access[rule_idx].perms = perms;
			}
			if(is_cond) {
				if (add_i_to_a(rule_idx, &r_list->num_av_access, &r_list->av_access) != 0) {
					assert(FALSE);
					return -1;
				}
			}
		}
		if(avdatum->specified & AVTAB_AUDITALLOW){
			rule_idx = insert_into_new_av_item(RULE_AUDITALLOW, src, tgt, cls, 
					enabled, policy);
			if(rule_idx < 0) return rule_idx;
			if(avtab_auditallow(avdatum)) {
				perms = decode_perm_mask(avtab_auditallow(avdatum), cls, avkey->target_class, bm, policy);
				assert(perms != NULL);
				policy->av_audit[rule_idx].perms = perms;
			}
			if(is_cond) {
				if (add_i_to_a(rule_idx, &r_list->num_av_audit, &r_list->av_audit) != 0) {
					assert(FALSE);
					return -1;
				}
			}
		}
		if(avdatum->specified & AVTAB_AUDITDENY) {
			__u32 dontaudit_mask;
			rule_idx = insert_into_new_av_item(RULE_DONTAUDIT, src, tgt, cls, 
					enabled, policy);
			if(rule_idx < 0) return rule_idx;
			/* these are stored as auditdeny rules; we need to translate into dontaudit */
			dontaudit_mask = ~avtab_auditdeny(avdatum);
			if(dontaudit_mask) {
				perms = decode_perm_mask(dontaudit_mask, cls, avkey->target_class, bm, policy);
				assert(perms != NULL);
				policy->av_audit[rule_idx].perms = perms;
			}
			if(is_cond) {
				if (add_i_to_a(rule_idx, &r_list->num_av_audit, &r_list->av_audit) != 0) {
					assert(FALSE);
					return -1;
				}
			}
		}
	} else {
		if (avdatum->specified & AVTAB_TRANSITION) {
			if(!binpol_validate_val(avtab_transition(avdatum), bm->t_num)) {
				assert(FALSE); /* debug aide */
				return -7;
			}
			dflt = bm->t_map[avtab_transition(avdatum)-1];
			assert(is_valid_type(policy, dflt, 1));
			rule_idx = insert_into_new_tt_item(RULE_TE_TRANS, src, tgt, cls, dflt,
					enabled, policy);
			if(is_cond) {
				if (add_i_to_a(rule_idx, &r_list->num_te_trans, &r_list->te_trans) != 0) {
					assert(FALSE);
					return -1;
				}
			}
		}
		if (avdatum->specified & AVTAB_CHANGE) {
			if(!binpol_validate_val(avtab_change(avdatum), bm->t_num)) {
				assert(FALSE); /* debug aide */
				return -7;
			}
			dflt = bm->t_map[avtab_change(avdatum)-1];
			assert(is_valid_type(policy, dflt, 1));
			rule_idx = insert_into_new_tt_item(RULE_TE_CHANGE, src, tgt, cls, dflt,
					enabled, policy);
			if(is_cond) {
				if (add_i_to_a(rule_idx, &r_list->num_te_trans, &r_list->te_trans) != 0) {
					assert(FALSE);
					return -1;
				}
			}
		}
		if (avdatum->specified & AVTAB_MEMBER) {
			if(!binpol_validate_val(avtab_member(avdatum), bm->t_num)) {
				assert(FALSE); /* debug aide */
				return -7;
			}
			dflt = bm->t_map[avtab_member(avdatum)-1];
			assert(is_valid_type(policy, dflt, 1));
			rule_idx = insert_into_new_tt_item(RULE_TE_MEMBER, src, tgt, cls, dflt,
					enabled, policy);
			if(is_cond) {
				if (add_i_to_a(rule_idx, &r_list->num_te_trans, &r_list->te_trans) != 0) {
					assert(FALSE);
					return -1;
				}
			}
		}
	}
	return rule_idx;
}

static int load_avtab_item(ap_fbuf_t *fb, FILE *fp, unsigned int opts, avtab_datum_t *avdatum, avtab_key_t *avkey)
{
	__u32 *buf;
	__u32 items, items2;
	
	memset(avkey, 0, sizeof(avtab_key_t));
	memset(avdatum, 0, sizeof(avtab_datum_t));
	
	buf = ap_read_fbuf(fb, sizeof(__u32), fp); 
	if(buf == NULL)	return fb->err;
	
	items2 = le32_to_cpu(buf[0]);
	buf = ap_read_fbuf(fb, sizeof(__u32)*items2, fp); 
	if(buf == NULL)	return fb->err;
	
	items = 0;
	avkey->source_type = le32_to_cpu(buf[items++]);
	avkey->target_type = le32_to_cpu(buf[items++]);
	avkey->target_class = le32_to_cpu(buf[items++]);
	avdatum->specified = le32_to_cpu(buf[items++]);
	if ((avdatum->specified & AVTAB_AV) &&
	    (avdatum->specified & AVTAB_TYPE)) {
		assert(FALSE); /* debug aide */
		return -7;
	}
	if (avdatum->specified & AVTAB_AV) {
		if(avdatum->specified & AVTAB_ALLOWED)
			avtab_allowed(avdatum) = le32_to_cpu(buf[items++]);
		if(avdatum->specified & AVTAB_AUDITDENY) 
			avtab_auditdeny(avdatum) = le32_to_cpu(buf[items++]);
		if(avdatum->specified & AVTAB_AUDITALLOW )
			avtab_auditallow(avdatum) = le32_to_cpu(buf[items++]);
	} else {		
		if(avdatum->specified & AVTAB_TRANSITION )
			avtab_transition(avdatum) = le32_to_cpu(buf[items++]);
		if(avdatum->specified & AVTAB_CHANGE )
			avtab_change(avdatum) = le32_to_cpu(buf[items++]);
		if(avdatum->specified & AVTAB_MEMBER )
			avtab_member(avdatum) = le32_to_cpu(buf[items++]);
	}	
	if (items != items2) {
		assert(FALSE); /* debug aide */
		return -7;
	}	
	return 0;
}

/* If r_list != NULL, then we're loading a conditional rule list (either true or false list).
 * In this case we also built the list, and take the enabled state from the avdatum.  
 *
 * IF r_list == NULL, we're loading the base (non-conditional) avtab in which case the state 
 * is always enabled, and there is no list list to build.
 */
static int load_avtab(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, 
		cond_rule_list_t *r_list, policy_t *policy)
{
	int rt;
	avtab_key_t avkey;
	avtab_datum_t avdatum;
	__u32 *buf, nel, i;
	bool_t keep = FALSE;
	
	INTERNAL_ASSERTION

	if (opts & POLOPT_TE_RULES)
		keep = TRUE;

	buf = ap_read_fbuf(fb, sizeof(__u32), fp); 
	if(buf == NULL) return fb->err;
	nel = le32_to_cpu(buf[0]);
	if (!nel) 
		return 0; /* empty AV table */
		
	for (i = 0; i < nel; i++) {
		rt = load_avtab_item(fb, fp, opts, &avdatum, &avkey);
		if (rt != 0)
			return rt;
		/* add the rule(s) to our policy */
		if(keep) {
			rt = add_binary_avrule(&avdatum, &avkey, bm, opts, r_list, policy);
			if(rt < 0)
				return rt;
		}
	}

	return 0;
}


static int load_cond_list(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf, nel, nel2, i, j, bool_val;
	bool_t keep = FALSE;
	int state, rt;
	cond_rule_list_t *t_list = NULL, *f_list = NULL;
	cond_expr_t *expr = NULL, *first, *last;
	
	INTERNAL_ASSERTION

	if (opts & (POLOPT_COND_EXPR|POLOPT_COND_TE_RULES))
		keep = TRUE;
	
	buf = ap_read_fbuf(fb, sizeof(__u32), fp); 
	if(buf == NULL) return fb->err;	
	nel = le32_to_cpu(buf[0]); /* # of conditionals in policy */
	/* read conditionals */
	for(i = 0; i < nel; i++) {
		buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
		if(buf == NULL) return fb->err;	
		state = le32_to_cpu(buf[0]);
		nel2 = le32_to_cpu(buf[1]); /* # of elements in expr */
		/* read this conditional's expression */
		first = last = NULL;
		for(j = 0; j < nel2; j++) {
			buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
			if(buf == NULL) return fb->err;	
			/* buf[0] expression type
			 * buf[1] expression bool val */
			if(keep) {
				expr = malloc(sizeof(cond_expr_t));
				if (expr == NULL) {
					fprintf(stderr, "out of memory\n");
					cond_free_expr(first);
					return -1;
				}
				memset(expr, 0, sizeof(cond_expr_t));
				expr->expr_type = le32_to_cpu(buf[0]);
				bool_val = le32_to_cpu(buf[1]);
				assert(bool_val <= bm->bool_num);
				expr->bool = bm->bool_map[bool_val-1];
				if (expr->expr_type == COND_BOOL && expr->bool >= policy->num_cond_bools) {
					free(expr); 
					expr = NULL; 
					continue;
				}
				if(j == 0) {
					first = expr;
				}
				else {
					last->next = expr;
				}
				last = expr;
			}
		}
		/* true list */
		if(keep) {
			t_list = (cond_rule_list_t *)malloc(sizeof(cond_rule_list_t));
			if(t_list == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			memset(t_list, 0, sizeof(cond_rule_list_t));
		}
		else {
			t_list = NULL;
		}
		rt = load_avtab(fb, fp, bm, opts, t_list, policy);
		if(rt < 0) {
			assert(FALSE);
			cond_free_rules_list(t_list);
			cond_free_expr(first);
			return rt;
		}
		/* false list */
		if(keep) {
			f_list = (cond_rule_list_t *)malloc(sizeof(cond_rule_list_t));
			if(f_list == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			memset(f_list, 0, sizeof(cond_rule_list_t));
		}
		else {
			f_list = NULL;
		}
		rt = load_avtab(fb, fp, bm, opts, f_list, policy);
		if(rt < 0) {
			assert(FALSE);
			cond_free_rules_list(t_list);
			cond_free_rules_list(f_list);
			cond_free_expr(first);
			return rt;
		}		
		if(keep) {
			rt = add_cond_expr_item(first, t_list, f_list, policy);
			if(rt < 0) {
				assert(FALSE);
				cond_free_rules_list(t_list);
				cond_free_rules_list(f_list);
				cond_free_expr(first);
				return -4;
			}
		}
	}

	return 0;
}

static int skip_mls_sens(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	/* see sens_read() */
	__u32 *buf, len;

	INTERNAL_ASSERTION
	
	buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
	if(buf == NULL)	return fb->err;
	/* buf[0] len
	 * buf[1] isalias
	 */
	
	/* name */
	len = le32_to_cpu(buf[0]);
	if(fseek(fp, len, SEEK_CUR) != 0)  
			 return -3;
	
	buf = ap_read_fbuf(fb, sizeof(__u32), fp);

	/* ebitmap */
	return skip_ebitmap(fb, fp);
}

static int skip_mls_cats(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	/* see cat_read() */
	__u32 *buf, len;

	INTERNAL_ASSERTION
	
	buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp); 
	if(buf == NULL)	return fb->err;
	/* buf[0] len
	 * buf[1] val 
	 * buf[2] isalias
	  */
	 len = le32_to_cpu(buf[0]);
	
	if(fseek(fp, len, SEEK_CUR) != 0)  
			 return -3;

	return 0;
}



/* main policy load function */
static int load_binpol(FILE *fp, unsigned int opts, policy_t *policy)
{
	__u32  *buf;
	size_t len, nprim, nel;
	unsigned int policy_ver, num_syms, i, j;
	int rt = 0, role_idx, type_idx;
	ap_fbuf_t *fb;
	ap_bmaps_t *bm = NULL;
	ebitmap_t *e;
	ap_alias_bmap_t *a;


	if(ap_init_fbuf(&fb) != 0)
		return -1;
	bm = ap_new_bmaps();
	if(bm == NULL)
		return -1;
	
	/* magic # and sz of policy string */
	buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp);
	if(buf == NULL) { rt = fb->err; goto err_return; }
	if (buf[0] != SELINUX_MAGIC) { rt = -2; goto err_return; }
	
	len = le32_to_cpu(buf[1]);
	if(len < 0) { rt = -3; goto err_return; }
	/* skip over the policy string */
	if(fseek(fp, sizeof(char)*len, SEEK_CUR) != 0) { rt = -3; goto err_return; }
	
	/* Read the version, config, and table sizes. */
	buf = ap_read_fbuf(fb, sizeof(__u32)*4, fp);
	if(buf == NULL) { rt = fb->err; goto err_return; }	
	for (i = 0; i < 4; i++)
		buf[i] = le32_to_cpu(buf[i]);
	
	policy_ver = buf[0];
	switch(policy_ver) {
	case POLICYDB_VERSION_MLS:
		if (set_policy_version(POL_VER_19, policy) != 0) {
			rt = -4;goto err_return;
		}
		mls_config = 1;
		num_syms = SYM_NUM;
		break;
	case POLICYDB_VERSION_NLCLASS:
		if(set_policy_version(POL_VER_18, policy) != 0)
			{ rt = -4; goto err_return; }
		num_syms = SYM_NUM - 2;
		break;
	case POLICYDB_VERSION_IPV6 :
		if(set_policy_version(POL_VER_17, policy) != 0)
			{ rt = -4; goto err_return; }
		num_syms = SYM_NUM - 2;
		break;
	case POLICYDB_VERSION_BOOL:
		if(set_policy_version(POL_VER_16, policy) != 0)
			{ rt = -4; goto err_return; }
		num_syms = SYM_NUM - 2;
		break;
	case POLICYDB_VERSION_BASE:
		if(set_policy_version(POL_VER_15, policy) != 0)
			{ rt = -4; goto err_return; }
		num_syms = SYM_NUM - 3;
		break;
	default: /* unsupported version */
		return -5;
		break;
	}
	
	/* symbol table size check (skip OCON num check)*/
	if (buf[2] != num_syms)	{ 
		assert(FALSE);
		rt = -4; 
		goto err_return; 
	}

	/* check for MLS stuff and skip over the # of levels */
	if(mls_config && buf[1]) {
		set_policy_version(POL_VER_19MLS, policy);
	}
	if(buf[1] && policy->version < POL_VER_MLS) { 
		rt = -6;
		goto err_return; 
	}
			
	/* read in symbol tables */
	for (i = 0; i < num_syms; i++) {
		buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
		if(buf == NULL) { rt = fb->err; goto err_return; }
		nprim = le32_to_cpu(buf[0]);
		nel = le32_to_cpu(buf[1]);
		/* allocate bmap structure */
		switch (i) {
		case 0:		/* common permissions */
			bm->cp_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->cp_map == NULL) {
				rt = -1;
				goto err_return;
			}
			bm->rev_cp_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->rev_cp_map == NULL) {
				rt = -1;
				goto err_return;
			}
			bm->cp_perm_map = (ap_permission_bmap_t *)malloc(sizeof(ap_permission_bmap_t) * nprim);
			if(bm->cp_perm_map == NULL) {
				rt = -1;
				goto err_return;
			}
			memset(bm->cp_perm_map, 0, sizeof(ap_permission_bmap_t) * nprim);
			bm->cp_num = nprim;
			break;
		case 1:		/* object classes */
			bm->cls_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->cls_map == NULL){
				rt = -1;
				goto err_return;
			}
			bm->cls_perm_map = (ap_permission_bmap_t *)malloc(sizeof(ap_permission_bmap_t) * nprim);
			if(bm->cls_perm_map == NULL) {
				rt = -1;
				goto err_return;
			}
			memset(bm->cls_perm_map, 0, sizeof(ap_permission_bmap_t) * nprim);
			bm->cls_num = nprim;
			break;
		case 2:		/* roles */
			bm->r_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->r_map == NULL){
				rt = -1;
				goto err_return;
			}
			bm->r_emap = (ebitmap_t *)malloc(sizeof(ebitmap_t) * nprim);
			if(bm->r_emap == NULL){
				rt = -1;
				goto err_return;
			}			
			bm->r_num = nprim;
			break;
		case 3:		/* types */
			bm->t_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->t_map == NULL){
				rt = -1;
				goto err_return;
			}
			/* for types, we need to initialize to invalid indicies
			 * because of the way aliases are handled in the binary policy */
			for(j = 0; j < nprim; j++) { bm->t_map[j] = -1;}
			bm->t_num = nprim;
			break;
		case 4:		/* users */
			bm->u_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->u_map == NULL){
				rt = -1;
				goto err_return;
			}
			bm->u_num = nprim;
			break;
		case 5:		/* conditional booleans */
			bm->bool_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->bool_map == NULL){
				rt = -1;
				goto err_return;
			}
			bm->bool_num = nprim;
			break;
		case 6:		/* MLS sensitivities */
		case 7:		/* MLS categories */
			/* we don't save any MLS stuff yet */
			break;
		default:	/* shouldn't get here */
			rt = -1; 
			goto err_return;
			break;
		}
		for (j = 0; j < nel; j++) {
			switch (i) {
			case 0:		/* common permissions */
				rt = load_common_perm(fb, fp, bm, opts, policy);
				if(rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case 1:		/* object classes */
				rt = load_class(fb, fp, bm, opts, policy);
				if(rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case 2:		/* roles */
				rt = load_role(fb, fp, bm, opts, policy);
				if(rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case 3:		/* types */
				rt = load_type(fb, fp, bm, opts, policy);
				if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case 4:		/* users */
				rt = load_user(fb, fp, bm, opts, policy);
				if(rt != 0) goto err_return;
				break;
			case 5:		/* conditional booleans */
				rt = load_bool(fb, fp, bm, opts, policy);
				if(rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case 6:		/* MLS levels */
				rt = skip_mls_sens(fb, fp, bm, opts, policy);
				if(rt < 0) return rt;
				break;
			case 7:		/* MLS categories */
				rt = skip_mls_cats(fb, fp, bm, opts, policy);
				if(rt < 0) goto err_return;
				break;
			default:	/* shouldn't get here */
				{ rt = -1; goto err_return; };
				break;
			}
		}
	}
	

	/* Process aliases */
	for(a = bm->alias_map; a != NULL; a = a->next) {
		assert(a->val <= bm->t_num); /* assert that the alias val is a valid type val */
		type_idx = bm->t_map[a->val-1]; 
		if(!is_valid_type_idx(type_idx, policy)) {
			assert(FALSE); /* debug aide */
			return -4;
		}
		rt = add_alias(type_idx, a->name, policy);
		if(rt == -1) {
			assert(FALSE); /* debug aide */
			return -4;
		}
	}
	
	/* Process role types; so far we've only stored the ebitmaps */
	if((opts & POLOPT_TYPES) &&  (opts & POLOPT_ROLES)){
		for(i = 0; i < bm->r_num; i++) {
			role_idx = bm->r_map[i];
			e = &(bm->r_emap[i]);
			for(j = ebitmap_startbit(e); j < ebitmap_length(e); j++) {
				if(ebitmap_get_bit(e, j)) {
					type_idx = bm->t_map[j];
					rt = add_type_to_role(type_idx, role_idx, policy);
					if(rt == -1) {
						assert(FALSE); /* debug aide */
						return -4;
					}
				}
			}
		}
	}
	
	/* AV tables */
	rt = load_avtab(fb, fp, bm, opts, NULL, policy);
	if(rt != 0) 
		return rt;

	/* conditional list */
	if (policy_ver >= POLICYDB_VERSION_BOOL) {
		rt = load_cond_list(fb, fp, bm, opts, policy);
		if(rt != 0) 
			return rt;
	}
	
	/* role trans */
	rt =load_role_trans(fb, fp, bm, opts, policy);
	if(rt != 0) 
		return rt;

	/* role allow */
	rt =load_role_allow(fb, fp, bm, opts, policy);
	if(rt != 0) 
		return rt;
	
	/* initial SIDs */
	rt =load_initial_sids(fb, fp, bm, opts, policy);
	if(rt != 0) 
		return rt;
	
	/* Rest is unsupported at this time */

	rt = 0;
err_return:
	ap_free_fbuf(&fb); 
	ap_free_bmaps(bm);
	return rt;
} 

/* Read a binary policy file into an apol policy structure.
 * Assumes that policy points to a new, initialized policy.
 *
 * Return codes:
 * 	 0	success
 *	-1	general error
 *	-2	wrong magic # for policy file
 * 	-3	problem reading binary policy file (file truncated?)
 * 	-4	problem adding to apol policy
 *	-5	unsupported binary policy version
 *	-6	MLS binary in a non-MLS apol tool build
 *	-7	problem with value index or other type of binary policy validation
 *	-8	Extended bitmap problem
 */
int ap_read_binpol_file(FILE *fp, unsigned int options, policy_t *policy)
{
	int rt;
	
	if(fp == NULL || policy == NULL)
		return -1;
		
	rt = load_binpol(fp, options, policy);
	policy->policy_type = POL_TYPE_BINARY;
	
	return rt;
}



/* checks whether provided file is a binary policy file.
 * will return the file rewounded */
bool_t ap_is_file_binpol(FILE *fp)
{
	size_t sz;
	__u32 ubuf;
	bool_t rt;
	
	if(fp == NULL)
		return FALSE;
		
	rewind(fp);
	sz = fread(&ubuf, sizeof(__u32), 1, fp);
	if(sz != 1)
		rt = FALSE; /* problem reading file */

	if(ubuf == SELINUX_MAGIC) 
		rt = TRUE;
	else
		rt = FALSE;
		
	rewind(fp);
	return rt;
}

/* returns the version number of the binary policy
 * will return the file rewound.
 *
 * return codes:
 * 	N	success - policy version returned
 *	-1	general error
 *	-2	wrong magic # for file
 *	-3	problem reading file
 */
int ap_binpol_version(FILE *fp)
{
	__u32  *buf;
	int rt, len;
	ap_fbuf_t *fb;
	
	if (fp == NULL)
		return -1;
	
	if(ap_init_fbuf(&fb) != 0)
		return -1;
	
	/* magic # and sz of policy string */
	buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp);
	if (buf == NULL) { rt = fb->err; goto err_return; }
	if (buf[0] != SELINUX_MAGIC) { rt = -2; goto err_return; }
	
	len = le32_to_cpu(buf[1]);
	if(len < 0) { rt = -3; goto err_return; }
	/* skip over the policy string */
	if(fseek(fp, sizeof(char)*len, SEEK_CUR) != 0) { rt = -3; goto err_return; }
	
	/* Read the version, config, and table sizes. */
	buf = ap_read_fbuf(fb, sizeof(__u32) * 1, fp);
	if(buf == NULL) { rt = fb->err; goto err_return; }	
	buf[0] = le32_to_cpu(buf[0]);
	
	rt = buf[0];
		
err_return:
	rewind(fp);
	ap_free_fbuf(&fb); 
	return rt;
}

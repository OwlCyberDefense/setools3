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
#include <netinet/in.h>

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

/* Read and store an ap_mls_range_t struct 
 * raw_sens is TRUE if we store the sensitvity value from the binary, or FALSE if we store the mapped value - a policy index. 
 * If we are calling this function before the sensitities mappings are create raw_sens must be FALSE in which case some post processing
 * is required before load_binpol returns in order to ultimately store valid policy indexes. */
static int load_mls_range(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy, ap_mls_range_t **range, bool_t raw_sens)
{
	__u32 *buf, nlvl;
	ebitmap_t ebitmap;
	ebitmap_node_t *node;
	int *cats_low, *cats_high = NULL, num_cats_low, num_cats_high = -1, rt, i, indx, sens_low, sens_high = -1;
	ap_mls_level_t *mls_level_low, *mls_level_high;

	INTERNAL_ASSERTION

	if (range == NULL) {
		assert(FALSE);
		return -1;
	}

	buf = ap_read_fbuf(fb, sizeof(__u32) * 2, fp); /* num items (1 or 2), first sensitivity */
	if(buf == NULL) return fb->err;
	nlvl = le32_to_cpu(buf[0]);
	
	/* low sens */
	sens_low = le32_to_cpu(buf[1]);
	if (!raw_sens)
		sens_low = bm->sens_map[sens_low-1];
	if (nlvl == 2) {
		/* optional high sens */
		buf = ap_read_fbuf(fb, sizeof(__u32), fp);
		if (buf == NULL) return fb->err;
	        sens_high = le32_to_cpu(buf[0]);
		if (!raw_sens)
			sens_high = bm->sens_map[sens_high-1];
	}
	/* low cats */
	ebitmap_init(&ebitmap);
	rt = ebitmap_read(fb, &ebitmap, fp);
	if (rt < 0) return rt;
	cats_low = (int*)malloc(sizeof(int) * ebitmap.highbit);
	if (cats_low == NULL) {
		fprintf(stderr, "Error: Out of memory\n.");
		return -1;
	}
	indx = 0;
	ebitmap_for_each_bit(&ebitmap, node, i) {
		if (ebitmap_node_get_bit(node, i)) {
			cats_low[indx++] = i;
		}
	}
	num_cats_low = indx;
	cats_low = realloc(cats_low, sizeof(int) * num_cats_low);

	if (nlvl == 2) {
		/* optional high cats */
		ebitmap_init(&ebitmap);
		rt = ebitmap_read(fb, &ebitmap, fp);
		if (rt < 0) return rt;
		cats_high = (int*)malloc(sizeof(int) * ebitmap.highbit);
		if (cats_high == NULL) {
			fprintf(stderr, "Error: Out of memory\n.");
			return -1;
		}
		indx = 0;
		ebitmap_for_each_bit(&ebitmap, node, i) {
			if (ebitmap_node_get_bit(node, i)) {
				cats_high[indx++] = i;
			}
		}		
		num_cats_high = indx;
		cats_high = realloc(cats_high, sizeof(int) * num_cats_high);
	} 

	/* create the low level*/
	mls_level_low = (ap_mls_level_t*)malloc(sizeof(ap_mls_level_t));
	if (mls_level_low == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	mls_level_low->sensitivity = sens_low;
	mls_level_low->categories = cats_low;
	mls_level_low->num_categories = num_cats_low;

	if (nlvl == 2) {
		/* optional second level */
		mls_level_high = (ap_mls_level_t*)malloc(sizeof(ap_mls_level_t));
		if (mls_level_high == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			return -1;
		}
		mls_level_high->sensitivity = sens_high;
		mls_level_high->categories = cats_high;
		mls_level_high->num_categories = num_cats_high;
	} else {
		mls_level_high = mls_level_low;
	}

	/* create a new range */
	*range = (ap_mls_range_t*)malloc(sizeof(ap_mls_range_t));
	if (*range == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	(*range)->low = mls_level_low;
	(*range)->high = mls_level_high;
	return 0;
}

/* Generates a fake attribute name based on the number of attributes currently in the policy. 
 * The result is guaranteed to be unique in the policy.(this is used by the binary policy 
 * parser because we don't have attribute names available) */
static char* get_fake_attrib_name(policy_t *policy)
{
	char *attrib=NULL;
	int sz, i = 0;

#define AP_FAKE_ATTRIB_PREFIX "attrib_"

	if (policy == NULL)
		return NULL;

	sz = strlen(AP_FAKE_ATTRIB_PREFIX) + 11; /* 11 is large enough for the biggest 32 bit number and a trailing NULL */
	attrib = (char*)malloc(sizeof(char)*sz); 
	if (attrib == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return NULL;
	}

	do {
		snprintf(attrib, sz, "%s%03i", AP_FAKE_ATTRIB_PREFIX, policy->num_attribs+i);
		i++;
	} while (get_attrib_idx(attrib, policy) >= 0);

	return attrib;
}

static int add_fake_attrib(policy_t *policy)
{
	char *attrib;
	int attrib_idx;

	/* TODO: will there be an aux file for looking up attrib names from attrib vals */
	attrib = get_fake_attrib_name(policy);
	if (attrib == NULL) 
		return -1;
	attrib_idx = add_attrib(FALSE, -1, policy, attrib);
	free(attrib);
	if (attrib_idx < 0) {
		return -1;
     	}
	return attrib_idx;
}

static int load_range_trans(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	int nel, i, dom, type, idx, idx_type;
	__u32 *buf32;
	ap_rangetrans_t *new_rngtr = NULL;
	ta_item_t *titem = NULL;

	INTERNAL_ASSERTION

	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if (buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32)*2, fp);
		dom = le32_to_cpu(buf32[0]);
		type = le32_to_cpu(buf32[1]);
		new_rngtr = add_new_rangetrans(policy);
		if (new_rngtr == NULL) {
			fprintf(stderr, "could not create new range_trans rule.\n");
			return -1;
		}
		new_rngtr->lineno = -1;
		/* source */
		titem = (ta_item_t*)malloc(sizeof(ta_item_t));
		if (titem == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			return -1;
		}
		idx = bm->t_map[dom-1];
		if (idx < 0) {
			idx = bm->a_map[dom-1];
			if (idx < 0) {
				assert(FALSE);
				return -1;
			}
			idx_type = IDX_ATTRIB;
		} else {
			idx_type = IDX_TYPE;
		}

		titem->idx = idx;
		titem->type = idx_type;
		if (insert_ta_item(titem, &(new_rngtr->src_types)) != 0) {
			assert(FALSE);
			return -1;
		}
		/* target */
		titem = (ta_item_t*)malloc(sizeof(ta_item_t));
		if (titem == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			return -1;
		}
		idx = bm->t_map[type-1];
		if (!is_valid_type_idx(idx, policy)) {
			idx = bm->a_map[type-1];
			if (!is_valid_attrib_idx(idx, policy)) {
				if (policy->version < POL_VER_20) {
					assert(FALSE);
					return -1;
				} else {
					idx = add_fake_attrib(policy);
					if (idx < 0)
						return -1;
					bm->a_map[type-1] = idx;
				}
			}
			idx_type = IDX_ATTRIB;
		} else {
			idx_type = IDX_TYPE;
		}

		titem->idx = idx;
		titem->type = idx_type;
		if (insert_ta_item(titem, &(new_rngtr->tgt_types)) != 0) {
			assert(FALSE);
			return -1;
		}

		if (buf32 == NULL) return fb->err;
		/* range_trans rules are always loaded after sensitivities so pass FALSE to store the policy indexes
		 * instead of the raws sensitivity values */  
		load_mls_range(fb, fp, bm, opts, policy, &(new_rngtr->range), FALSE);
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

static int load_user_dflt_mls_level(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy, ap_mls_level_t **mls_level)
{
	__u32 *buf;
	ebitmap_t ebitmap;
	ebitmap_node_t *node;
	int sens, rt, i, indx, num_categories, *categories;

	INTERNAL_ASSERTION

	if (mls_level == NULL) {
		assert(FALSE);
		return -1;
	}

	buf = ap_read_fbuf(fb, sizeof(__u32), fp);
	if (buf == NULL)
		return fb->err;

	/* we load users before the sensitivity mapping, so we will post process this raw value later */
	sens = le32_to_cpu(buf[0]);

	/* read categories bitmap */
	ebitmap_init(&ebitmap);
	rt = ebitmap_read(fb, &ebitmap, fp);
	if (rt < 0) return rt;
	categories = (int*)malloc(sizeof(int) * ebitmap.highbit);
	if (categories == NULL) {
		fprintf(stderr, "Error: Out of memory\n.");
		return -1;
	}
	indx = 0;
	ebitmap_for_each_bit(&ebitmap, node, i) {
		if (ebitmap_node_get_bit(node, i)) {
			categories[indx++] = i;
		}
	}
	num_categories = indx;
	categories = realloc(categories, num_categories * sizeof(int));

	*mls_level = malloc(sizeof(ap_mls_level_t));
	if (*mls_level == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	(*mls_level)->categories = categories;
	(*mls_level)->num_categories = num_categories;
	(*mls_level)->sensitivity = sens;

	return rt; 
}

static int load_mls_level(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf;
	ebitmap_t ebitmap;
	ebitmap_node_t *node;
	int sens, rt, i, indx, num_categories, *categories;

	INTERNAL_ASSERTION

	buf = ap_read_fbuf(fb, sizeof(__u32), fp);
	if (buf == NULL)
		return fb->err;
	sens = le32_to_cpu(buf[0]);
	/* this is where we store the sensitivity precedence information. */
	bm->sens_map[sens-1] = policy->num_sensitivities-1;

	/* read categories bitmap */
	ebitmap_init(&ebitmap);
	rt = ebitmap_read(fb, &ebitmap, fp);
	if (rt < 0) return rt;
	categories = (int*)malloc(sizeof(int) * ebitmap.highbit);
	if (categories == NULL) {
		fprintf(stderr, "Error: Out of memory\n.");
		return -1;
	}
	indx = 0;
	ebitmap_for_each_bit(&ebitmap, node, i) {
		if (ebitmap_node_get_bit(node, i)) {
			categories[indx++] = i;
		}
	}
	num_categories = indx;
	categories = realloc(categories, num_categories * sizeof(int));
	rt = add_mls_level(bm->sens_map[sens-1], categories, num_categories, policy);
	if (rt < 0) {
		free(categories);
	}
	return rt; 
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
	__u32 val = 0, num_cp = 0;
	
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
	unsigned char *kbuf;
	char *key;
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
		key = (char *)malloc(sizeof(char)*(len+1));
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
	unsigned char *kbuf;
	char *key, *cbuf;
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
		key = (char *)malloc(sizeof(char)*(len+1));
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
			idx2 = get_common_perm_idx((const char *)cbuf, policy);
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
			fprintf(stderr, "Error: Out of memory\n");
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
	unsigned char *kbuf;
	char *key;
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
		key = (char *)malloc(sizeof(char)*(len+1));
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
	unsigned char *kbuf;
	char *key;
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
		key = (char *)malloc(sizeof(char)*(len+1));
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

static int load_type_attr_map(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	int i, j, rt;
	ebitmap_node_t *tnode;
	ebitmap_t *type_attr_map;
	char *attrib;

	INTERNAL_ASSERTION
		
	if (policy->version < POL_VER_20) {
		assert(FALSE);
		return -1;
	}

	type_attr_map = malloc(bm->t_num * sizeof(ebitmap_t));
	if (type_attr_map == NULL) return -1;

	for (i = 0; i < bm->t_num; i++)
		ebitmap_init(&type_attr_map[i]);
	
	for (i = 0; i < bm->t_num; i++) {
		rt = ebitmap_read(fb, &type_attr_map[i], fp);
		if (rt < 0) goto bad;

		if (bm->t_map[i] == -1)
			continue;

		ebitmap_for_each_bit(&type_attr_map[i], tnode, j) {

			if (ebitmap_node_get_bit(tnode, j) && i != j) { /* the bit is high and not a type */

				if (is_valid_type_idx(bm->t_map[j], policy)) {
					assert(FALSE);
					rt = -1;
					goto bad;
				}
				if (!is_valid_attrib_idx(bm->a_map[j], policy)) { /* the attrib didn't occur in the avtab */
					rt = add_fake_attrib(policy);
					if (rt < 0) goto bad;
					bm->a_map[j] = rt;
				}
				if (get_attrib_name(bm->a_map[j], &attrib, policy) < 0) {
					assert(FALSE);
					rt = -1;
					goto bad;
				}
				rt = add_attrib_to_type(bm->t_map[i], attrib, policy);
				free(attrib);
				if (rt < 0) goto bad;
			}
		}
	}
	
	rt = 0;
bad:
	ebitmap_destroy(type_attr_map);
	return rt;
}

static int load_user(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 *buf, val;
	size_t len;
	unsigned char *kbuf;
	char *key;
	bool_t keep = FALSE;
	int i, rt, idx = -1;
	ebitmap_t e;
	ap_mls_level_t *mls_level = NULL;
	ap_mls_range_t *mls_range = NULL;

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
		key = (char *)malloc(sizeof(char)*(len+1));
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
		/* users are always loaded before the sensitivity mappings, so pass TRUE to store the 
		 * raw sensitivity values and do the post processing on these values before load_binpol
		 * returns. */
		rt = load_mls_range(fb, fp, bm, opts, policy, &mls_range, TRUE);
		if (rt < 0) return -1;
		if (keep) {
			policy->users[idx].range = mls_range;
		} else {
			ap_mls_range_free(mls_range);
			mls_range = NULL;
		}
		rt = load_user_dflt_mls_level(fb, fp, bm, opts, policy, &mls_level);
		if (rt < 0) return -1;
		if (keep) {
			policy->users[idx].dflt_level = mls_level;
		} else {
			ap_mls_level_free(mls_level);
			mls_level = NULL;
		}
	}

	return 0;
}

static int load_bool(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	__u32 len, *buf, val;
	bool_t keep = FALSE, state;
	char *key;
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
		key = (char *)malloc(sizeof(char)*(len+1));
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
					fprintf(stderr, "Error: Out of memory\n");
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
				fprintf(stderr, "Error: Out of memory\n");
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
				fprintf(stderr, "Error: Out of memory\n");
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
					fprintf(stderr, "Error: Out of memory\n");
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
				fprintf(stderr, "Error: Out of memory\n");
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
				fprintf(stderr, "Error: Out of memory\n");
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

static int load_security_context(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy, security_con_t **context)
{
	int rt, user, role, type;
	__u32 *buf32;

	INTERNAL_ASSERTION

	if (context == NULL) {
		assert(FALSE);
		return -1;
	}
	*context = (security_con_t*)malloc(sizeof(security_con_t));
	if (*context == NULL) {
		fprintf(stderr, "Error: Out of memory.\n");
		return -1;
	}
	memset(*context, 0, sizeof(security_con_t));
	buf32 = ap_read_fbuf(fb, sizeof(__u32)*3, fp); /* user, role, type */
	if (buf32 == NULL) {
		rt = fb->err;
		goto err;
	}
	user = le32_to_cpu(buf32[0]);
	role = le32_to_cpu(buf32[1]);
	type = le32_to_cpu(buf32[2]);

	(*context)->user = bm->u_map[user-1];
	(*context)->role = bm->r_map[role-1];
	(*context)->type = bm->t_map[type-1];

	if (policy->version >= POL_VER_19) {
		/* security contexts are always loaded after sensitivities so pass FALSE to store the policy indexes
		 * instead of the raws sensitivity values */ 
		rt = load_mls_range(fb, fp, bm, opts, policy, &((*context)->range), FALSE);
		assert((*context)->range->low);
		if (rt < 0) goto err;
	}
	return 0;
err:
	if (*context) {
		if ((*context)->range)
			ap_mls_range_free((*context)->range);
		free(*context);
		*context = NULL;
	}
	return rt;
}

static int load_initial_sids(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	int nel, i, rt;
	__u32 *buf32;
	security_con_t *context;

	INTERNAL_ASSERTION
	
	if (opts & POLOPT_INITIAL_SIDS)
		keep = TRUE;
	
	/* TODO: Currently initial SIDs not supported for binary policies.  The reason is that
	 * the binary policy does not store the symbolic name of initial sids, yet apol
	 * assumes these names and keys off of them.  Thus until we resolve this issue, initial
	 * sids will not be supported */

	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);   /* sid */
		if (buf32 == NULL) return fb->err;

		rt = load_security_context(fb, fp, bm, opts, policy, &context);
		if (rt < 0) return fb->err;
	}
	return 0;
}

static int load_ocon_netif(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	int nel, len, i, rt;
	__u32 *buf32;
	security_con_t *devcon = NULL, *pktcon = NULL;
	char *iface = NULL;

	INTERNAL_ASSERTION
	
	if (opts & POLOPT_OCONTEXT)
		keep = TRUE;
	
	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
		if(buf32 == NULL) return fb->err;
		len = le32_to_cpu(buf32[0]);

		buf32 = ap_read_fbuf(fb, len, fp); /* interface name */
		if (buf32 == NULL) return fb->err;

		iface = malloc(sizeof(char) * (len+1));
		memcpy(iface, buf32, len);
		iface[len] = '\0';
		
		rt = load_security_context(fb, fp, bm, opts, policy, &devcon); /* device context */
		if (rt < 0) return fb->err;

		rt = load_security_context(fb, fp, bm, opts, policy, &pktcon); /* packed context */
		if (rt < 0) return fb->err;
		
		if (keep) {
			rt = add_netifcon(iface, devcon, pktcon, policy);
			if (rt == 0) 
				continue;
			else
				fprintf(stderr, "Error: failed to add netifcon for %s.\n", iface);
		}
		security_con_destroy(devcon); 
		devcon = NULL;
		security_con_destroy(pktcon); 
		pktcon = NULL;
		free(iface); 
		iface = NULL;
	}
	return 0;
}

static int skip_ocon_fs(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	int nel, len, i, rt;
	__u32 *buf32;
	security_con_t *devcon, *pktcon;

	INTERNAL_ASSERTION
	
	if (opts & POLOPT_OCONTEXT)
		keep = TRUE;
	
	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
		if(buf32 == NULL) return fb->err;
		len = le32_to_cpu(buf32[0]);

		buf32 = ap_read_fbuf(fb, len, fp); /* name */
		if (buf32 == NULL) return fb->err;

		rt = load_security_context(fb, fp, bm, opts, policy, &devcon); /* context 1 */
		if (rt < 0) return fb->err;
		security_con_destroy(devcon);
		rt = load_security_context(fb, fp, bm, opts, policy, &pktcon); /* context 2 */
		if (rt < 0) return fb->err;
		security_con_destroy(pktcon);
	}
	
	return 0;
}

static int load_ocon_port(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	int nel, i, rt, proto, lowport, highport;
	__u32 *buf32;
	security_con_t *context;

	INTERNAL_ASSERTION
	
	if (opts & POLOPT_OCONTEXT)
		keep = TRUE;

	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32)*3, fp); /* protocol, low_port, high_port */
		if (buf32 == NULL) return fb->err;

		proto = le32_to_cpu(buf32[0]);
		lowport = le32_to_cpu(buf32[1]);
		highport = le32_to_cpu(buf32[2]);

		if (proto != AP_TCP_PROTO && proto != AP_UDP_PROTO && proto != AP_ESP_PROTO) {
			assert(FALSE);
			return -1;
		}
		
		rt = load_security_context(fb, fp, bm, opts, policy, &context);
		if (rt < 0) return fb->err;

		if (keep) {
			rt = add_portcon(proto, lowport, highport, context, policy);
			if (rt == 0)
				continue;
			else
				fprintf(stderr, "Error: failed to add portcon for (%i-%i)\n", lowport, highport);
		}
		security_con_destroy(context);
		context = NULL;
	}

	return 0;
}

static int load_ocon_node(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	int nel, i, rt;
	__u32 *buf32;
	security_con_t *context;
	uint32_t mask[4], addr[4];
	
	INTERNAL_ASSERTION

	if (opts & POLOPT_OCONTEXT)
		keep = TRUE;
	
	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32)*2, fp); /* addr, mask */
		if (buf32 == NULL) return fb->err;

		addr[3] = ntohl(le32_to_cpu(buf32[0]));
		addr[2] = addr[1] = addr[0] = 0;
		mask[3] = ntohl(le32_to_cpu(buf32[1]));
		mask[2] = mask[1] = mask[0] = 0;

		rt = load_security_context(fb, fp, bm, opts, policy, &context);
		if (rt < 0) return fb->err;

		if (keep) {
			rt = add_nodecon(AP_IPV4, addr, mask, context, policy);
			if (rt == 0)
				continue;
			else
				fprintf(stderr, "Error: failed to add nodecon");
		}
		security_con_destroy(context);
	}
	return 0;
}

static int load_ocon_fsuse(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	int nel, len, i, rt, behav;
	__u32 *buf32;
	security_con_t *context;
	char *fstype;
	
	INTERNAL_ASSERTION
	
	if (opts & POLOPT_OCONTEXT)
		keep = TRUE;
	
	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32)*2, fp); /* behavior, len */
		if (buf32 == NULL) return fb->err;
		behav = le32_to_cpu(buf32[0]);
		if (behav != AP_FS_USE_PSID && behav != AP_FS_USE_XATTR && behav != AP_FS_USE_TASK && behav != AP_FS_USE_TRANS) {
			assert(FALSE);
			return -1;
		}
		len = le32_to_cpu(buf32[1]);
		fstype = malloc(sizeof(char) * (len+1));
		if (fstype == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			return -1;
		}
		buf32 = ap_read_fbuf(fb, len, fp); /* fstype */
		if (buf32 == NULL) return fb->err;
		memcpy(fstype, buf32, len);
		fstype[len] = '\0';
		rt = load_security_context(fb, fp, bm, opts, policy, &context);
		if (rt < 0) return fb->err;
		
		if (keep) {
			rt = add_fs_use(behav, fstype, context, policy);
			if (rt == 0)
				continue;
			else
				fprintf(stderr, "Error: failed to add fs_use for %s\n", fstype);
		}
		free(fstype);
		fstype = NULL;
		security_con_destroy(context);
		context = NULL;
	}

	return 0;
}

static int load_ocon_node6(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	int nel, i, rt;
	__u32 *buf32;
	security_con_t *context;
	uint32_t mask[4], addr[4];

	INTERNAL_ASSERTION
	
	if (opts & POLOPT_OCONTEXT)
		keep = TRUE;

	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if(buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32)*8, fp); /* v6 addr , mask*/
		if (buf32 == NULL) return fb->err;

		addr[0] = ntohl(le32_to_cpu(buf32[0]));
		addr[1] = ntohl(le32_to_cpu(buf32[1]));
		addr[2] = ntohl(le32_to_cpu(buf32[2]));
		addr[3] = ntohl(le32_to_cpu(buf32[3]));

		mask[0] = ntohl(le32_to_cpu(buf32[4]));
		mask[1] = ntohl(le32_to_cpu(buf32[5]));
		mask[2] = ntohl(le32_to_cpu(buf32[6]));
		mask[3] = ntohl(le32_to_cpu(buf32[7]));

		rt = load_security_context(fb, fp, bm, opts, policy, &context);
		if (rt < 0) return fb->err;
		if (keep) {
			rt = add_nodecon(AP_IPV6, addr, mask, context, policy);
			if (rt ==  0) 
				continue;
		}
		security_con_destroy(context);
	}
	return 0;
}

static int load_genfs_contexts(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	bool_t keep = FALSE;
	int nel, nel2, len, i, j, rt, filetype;
	__u32 *buf32;
	security_con_t *context;
	char *fstype, *path;

	if (opts & POLOPT_OCONTEXT)
		keep = TRUE;

	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
	if (buf32 == NULL) return fb->err;
	nel = le32_to_cpu(buf32[0]);

	for (i=0; i < nel; i++) {
		buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
		if (buf32 == NULL) return fb->err;
		len = le32_to_cpu(buf32[0]);
		
		buf32 = ap_read_fbuf(fb, len, fp); /* fstype */
		if (buf32 == NULL) return fb->err;
		fstype = malloc(sizeof(char) * (len+1));
		if (fstype == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			return -1;
		}
		memcpy(fstype, buf32, len);
		fstype[len] = '\0';
		if (keep) {
			rt = add_genfscon(fstype, policy);
			if (rt < 0) {
				fprintf(stderr, "Error: failed to add genfscon for %s\n", fstype);
				free(fstype);
				return -1;
			}
		}

		buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
		if (buf32 == NULL) return fb->err;
		nel2 = le32_to_cpu(buf32[0]);

		for (j=0; j < nel2; j++) {
			buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
			if (buf32 == NULL) return fb->err;
			len = le32_to_cpu(buf32[0]);

			buf32 = ap_read_fbuf(fb, len, fp); /* path */
			if (buf32 == NULL) return fb->err;
			path = malloc(sizeof(char) * (len+1));
			if (path == NULL) {
				fprintf(stderr, "Error: Out of memory\n");
				return -1;
			}
			memcpy(path, buf32, len);
			path[len] = '\0';
			buf32 = ap_read_fbuf(fb, sizeof(__u32), fp); /* filetype */
			if (buf32 == NULL) return fb->err;
			filetype = le32_to_cpu(buf32[0]);
			if (filetype == 0)
				filetype = FILETYPE_ANY;

			if (filetype != FILETYPE_REG && filetype != FILETYPE_DIR && filetype != FILETYPE_LNK &&
			    filetype != FILETYPE_CHR && filetype != FILETYPE_BLK && filetype != FILETYPE_SOCK &&
			    filetype != FILETYPE_FIFO && filetype != FILETYPE_ANY) {
				assert(FALSE);
				return -1;
			}
			
			rt = load_security_context(fb, fp, bm, opts, policy, &context);
			if (context->range->low == NULL) assert(FALSE);
			if (rt < 0) return rt;
			if (keep) {
				rt = add_path_to_genfscon(&(policy->genfscon[policy->num_genfscon-1]), path, filetype, context);
				assert(context->range->low);
				if (rt == 0)
					continue;
				else
					fprintf(stderr, "Erorr: failed to add path \"%s\" for genfscon \"%s\"\n", path, fstype);
			} 
			free(path);
			path = NULL;
			security_con_destroy(context);
			context = NULL;
		}
	}
	return 0;
}

static int insert_into_new_tt_item(int rule_type, int src, unsigned int src_id, int tgt, unsigned int tgt_id, int cls, int def_type,
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

	if (policy->version < POL_VER_20) {
		if (src_id != IDX_TYPE || tgt_id != IDX_TYPE) 
		{ assert(FALSE); return -4; }
	} else {
		if ( (src_id != IDX_TYPE && src_id != IDX_ATTRIB) || 
		     (tgt_id != IDX_TYPE && tgt_id != IDX_ATTRIB)) 
		{ assert(FALSE); return -4;}
	}
	
	/* source */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	titem->type = src_id;
	titem->idx = src;
	if(insert_ta_item(titem, &(item->src_types)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	
	/* target */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	titem->type = tgt_id;
	titem->idx = tgt;
	if(insert_ta_item(titem, &(item->tgt_types)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	/* class */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
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



static int insert_into_new_av_item(int rule_type, int src, unsigned int src_id, int tgt, unsigned int tgt_id, int cls, 
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

	if (policy->version < POL_VER_20) {
		if (src_id != IDX_TYPE || tgt_id != IDX_TYPE) 
		{ assert(FALSE); return -4; }
	} else {
		if ( (src_id != IDX_TYPE && src_id != IDX_ATTRIB) || 
		     (tgt_id != IDX_TYPE && tgt_id != IDX_ATTRIB)) 
		{ assert(FALSE); return -4;}
	}

	/* source */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	titem->type = src_id;
	titem->idx = src;
	if(insert_ta_item(titem, &(item->src_types)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	
	/* target */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	titem->type = tgt_id;
	titem->idx = tgt;
	if(insert_ta_item(titem, &(item->tgt_types)) != 0) {
		assert(FALSE); /* debug aide */
		return -4;
	}
	/* class */
	titem = (ta_item_t *)malloc(sizeof(ta_item_t));
	if(titem == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
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
				fprintf(stderr, "Error: Out of memory \n");
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
	int rt;
	ta_item_t *perms;
	bool_t is_cond, enabled;
	unsigned int src_id = IDX_TYPE, tgt_id = IDX_TYPE;

	assert(avdatum != NULL && avkey != NULL && bm != NULL && policy != NULL);
	src = tgt = cls = dflt = rule_idx = -1;
	is_cond = (r_list != NULL);
	enabled = (is_cond ? binpol_enabled(avdatum->specified) : TRUE);

	if(avdatum->specified & (AVTAB_AV|AVTAB_TYPE)) {
		
		/* re-map the src, tgt, and class indicies */
		
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
		assert(is_valid_obj_class_idx(cls, policy));

		if (policy->version >= POL_VER_20) {
			if (!is_valid_type(policy, src, TRUE)) {
				src_id = IDX_ATTRIB;
				src = bm->a_map[avkey->source_type-1];
				if (!is_valid_attrib_idx(src, policy)) {
					rt = add_fake_attrib(policy);
					if (rt < 0) return rt;
					bm->a_map[avkey->source_type-1] = rt;
					src = rt;
				}
			}
			if (!is_valid_type(policy, tgt, TRUE)) {
				tgt_id = IDX_ATTRIB;
				tgt = bm->a_map[avkey->target_type-1];
				if (!is_valid_attrib_idx(tgt, policy)) {
					rt = add_fake_attrib(policy);
					if (rt < 0) return rt;
					bm->a_map[avkey->target_type-1] = rt;
					tgt = rt;
				}
			}
		} else {
			if (!is_valid_type(policy, src, TRUE) || !is_valid_type(policy, tgt, TRUE)) {
				assert(FALSE);
				return -1;
			}
		}
	}

	if (avdatum->specified & AVTAB_AV) {
		
		if(avdatum->specified & AVTAB_ALLOWED) {
			rule_idx = insert_into_new_av_item(RULE_TE_ALLOW, src, src_id, tgt, tgt_id, cls, 
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
			rule_idx = insert_into_new_av_item(RULE_AUDITALLOW, src, src_id, tgt, tgt_id, cls, 
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
			rule_idx = insert_into_new_av_item(RULE_DONTAUDIT, src, src_id, tgt, tgt_id, cls, 
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
			rule_idx = insert_into_new_tt_item(RULE_TE_TRANS, src, src_id, tgt, tgt_id, cls, dflt,
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
			rule_idx = insert_into_new_tt_item(RULE_TE_CHANGE, src, src_id, tgt, tgt_id, cls, dflt,
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
			rule_idx = insert_into_new_tt_item(RULE_TE_MEMBER, src, src_id, tgt, tgt_id, cls, dflt,
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

static int load_avtab_item(ap_fbuf_t *fb, FILE *fp, unsigned int opts, avtab_datum_t *avdatum, avtab_key_t *avkey, int polver)
{
	__u32 *buf32;
	__u32 items, items2;

	__u16 *buf16;

	memset(avkey, 0, sizeof(avtab_key_t));
	memset(avdatum, 0, sizeof(avtab_datum_t));

	if (polver >= POL_VER_20) {
		/* Read the new avtab format */
		buf16 = ap_read_fbuf(fb, sizeof(__u16)*4, fp);
		if (buf16 == NULL)
			return fb->err;
		items = 0;
		avkey->source_type = le16_to_cpu(buf16[items++]);
		avkey->target_type = le16_to_cpu(buf16[items++]);
		avkey->target_class = le16_to_cpu(buf16[items++]);
		avdatum->specified = le16_to_cpu(buf16[items++]);
		
		buf32 = ap_read_fbuf(fb, sizeof(__u32), fp);
		if (buf32 == NULL)
			return fb->err;

		switch (avdatum->specified & (AVTAB_AV|AVTAB_TYPE)) {
		case AVTAB_ALLOWED:
			avtab_allowed(avdatum) = le32_to_cpu(buf32[0]);
			break;
		case AVTAB_AUDITDENY: 
			avtab_auditdeny(avdatum) = le32_to_cpu(buf32[0]);
			break;
		case AVTAB_AUDITALLOW:
			avtab_auditallow(avdatum) = le32_to_cpu(buf32[0]);
			break;
		case AVTAB_TRANSITION:
			avtab_transition(avdatum) = le32_to_cpu(buf32[0]);
			break;
		case AVTAB_CHANGE:
			avtab_change(avdatum) = le32_to_cpu(buf32[0]);
			break;
		case AVTAB_MEMBER:
			avtab_member(avdatum) = le32_to_cpu(buf32[0]);
			break;
		default: /* only one rule type will be present in version 20+ */
			assert(FALSE); /* debug aide */
			return -7;
			break;
		}
		return 0;
	}
	
	buf32 = ap_read_fbuf(fb, sizeof(__u32), fp); 
	if(buf32 == NULL)	return fb->err;

	items2 = le32_to_cpu(buf32[0]);
	buf32 = ap_read_fbuf(fb, sizeof(__u32)*items2, fp); 
	if(buf32 == NULL)	return fb->err;

	items = 0;
	avkey->source_type = le32_to_cpu(buf32[items++]);
	avkey->target_type = le32_to_cpu(buf32[items++]);
	avkey->target_class = le32_to_cpu(buf32[items++]);
	avdatum->specified = le32_to_cpu(buf32[items++]);
	if ((avdatum->specified & AVTAB_AV) &&
	    (avdatum->specified & AVTAB_TYPE)) {
		assert(FALSE); /* debug aide */
		return -7;
	}
	if (avdatum->specified & AVTAB_AV) {
		if(avdatum->specified & AVTAB_ALLOWED)
			avtab_allowed(avdatum) = le32_to_cpu(buf32[items++]);
		if(avdatum->specified & AVTAB_AUDITDENY) 
			avtab_auditdeny(avdatum) = le32_to_cpu(buf32[items++]);
		if(avdatum->specified & AVTAB_AUDITALLOW )
				avtab_auditallow(avdatum) = le32_to_cpu(buf32[items++]);
	} else {		
		if(avdatum->specified & AVTAB_TRANSITION )
			avtab_transition(avdatum) = le32_to_cpu(buf32[items++]);
		if(avdatum->specified & AVTAB_CHANGE )
			avtab_change(avdatum) = le32_to_cpu(buf32[items++]);
		if(avdatum->specified & AVTAB_MEMBER )
			avtab_member(avdatum) = le32_to_cpu(buf32[items++]);
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
		rt = load_avtab_item(fb, fp, opts, &avdatum, &avkey, policy->version);
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
					fprintf(stderr, "Error: Out of memory\n");
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
				fprintf(stderr, "Error: Out of memory\n");
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
				fprintf(stderr, "Error: Out of memory\n");
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

static int load_mls_sens(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	/* see sens_read() */
	__u32 *buf, len, isalias;
	int rt;
	char *name = NULL;

	INTERNAL_ASSERTION
	
	buf = ap_read_fbuf(fb, sizeof(__u32)*2, fp); 
	if(buf == NULL)	return fb->err;

	len = le32_to_cpu(buf[0]);
	isalias = le32_to_cpu(buf[1]);

	/* name */
	buf = ap_read_fbuf(fb, len, fp);
	if (buf == NULL) return fb->err;
	name = (char*)malloc(sizeof(char)*(len+1));
	if (name == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	memcpy(name, buf, len);
	name[len] = '\0';

	if (isalias) {
		rt = add_sensitivity_alias(policy->num_sensitivities-1, name, policy);
		if (rt < 0) goto err;
		skip_mls_level(fb, fp, bm, opts, policy);
	} else {
		rt = add_sensitivity(name, NULL, policy); /* no aliases */
		if (rt < 0) goto err;
		load_mls_level(fb, fp, bm, opts, policy);
	}

	return 0;
err:
	free(name);
	return rt;
}

static int load_mls_cats(ap_fbuf_t *fb, FILE *fp, ap_bmaps_t *bm, unsigned int opts, policy_t *policy)
{
	/* see cat_read() */
	__u32 *buf, len;
	int isalias, val, rt;
	char *name;

	INTERNAL_ASSERTION
	
	buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp); 
	if(buf == NULL)	return fb->err;
	len = le32_to_cpu(buf[0]);
	val = le32_to_cpu(buf[1]);
	isalias = le32_to_cpu(buf[2]);

	/* name */
	buf = ap_read_fbuf(fb, len, fp);
	if (buf == NULL) return fb->err;
	name = (char*)malloc(sizeof(char)*(len+1));
	if (name == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return -1;
	}
	memcpy(name, buf, len);
	name[len] = '\0';
	
	if (isalias) {
		rt = add_category_alias(val-1, name, policy);
		if (rt < 0) goto err;
	} else {
		rt = add_category(name, val-1, NULL, policy); /* no aliases */
		if (rt < 0) goto err;
	}
	return 0;
err:
	free(name);
	return rt;
}

/* main policy load function */
static int load_binpol(FILE *fp, unsigned int opts, policy_t *policy)
{
	__u32  *buf;
	size_t len, nprim, nel;
	unsigned int policy_ver, num_syms, i, j, num_ocons, tmp;
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
	buf[0] = le32_to_cpu(buf[0]);
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

	case POLICYDB_VERSION_AVTAB:
		if (set_policy_version(POL_VER_20, policy) != 0) {
			rt = -4; goto err_return; 
		}
		mls_config = 1;
		num_syms = SYM_NUM;
		num_ocons = OCON_NUM;
		break;
	case POLICYDB_VERSION_MLS:
		if (set_policy_version(POL_VER_19, policy) != 0) {
			rt = -4; goto err_return;
		}
		mls_config = 1;
		num_syms = SYM_NUM;
		num_ocons = OCON_NUM;
		break;
	case POLICYDB_VERSION_NLCLASS:
		if(set_policy_version(POL_VER_18, policy) != 0)
			{ rt = -4; goto err_return; }
		num_syms = SYM_NUM - 2;
		num_ocons = OCON_NUM;
		break;
	case POLICYDB_VERSION_IPV6 :
		if(set_policy_version(POL_VER_17, policy) != 0)
			{ rt = -4; goto err_return; }
		num_syms = SYM_NUM - 2;
		num_ocons = OCON_NUM;
		break;
	case POLICYDB_VERSION_BOOL:
		if(set_policy_version(POL_VER_16, policy) != 0)
			{ rt = -4; goto err_return; }
		num_syms = SYM_NUM - 2;
		num_ocons = OCON_NUM - 1;
		break;
	case POLICYDB_VERSION_BASE:
		if(set_policy_version(POL_VER_15, policy) != 0)
			{ rt = -4; goto err_return; }
		num_syms = SYM_NUM - 3;
		num_ocons = OCON_NUM - 1;
		break;
	default: /* unsupported version */
		return -5;
		break;
	}
	
	/* symbol table size check (skip OCON num check)*/
	if (buf[2] != num_syms || buf[3] != num_ocons)	{ 
		assert(FALSE);
		rt = -4; 
		goto err_return; 
	}

	/* check for MLS stuff and skip over the # of levels */
	if(mls_config && buf[1]) {
			policy->mls = TRUE;
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
		case SYM_COMMONS:	/* common permissions */
			bm->cp_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->cp_map == NULL) {
				rt = -1;
				goto err_return;
			}
			bm->rev_cp_map = (__u32 *)malloc(sizeof(__u32) * nprim);
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
		case SYM_CLASSES:	/* object classes */
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
		case SYM_ROLES:		/* roles */
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
		case SYM_TYPES:		/* types */
			bm->t_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->t_map == NULL){
				rt = -1;
				goto err_return;
			}
			/* for types, we need to initialize to invalid indicies
			 * because of the way aliases are handled in the binary policy */
			for(j = 0; j < nprim; j++) { bm->t_map[j] = -1; }
			bm->t_num = nprim;

			/* support attribs */
			if (policy->version >= POL_VER_20) {
				bm->a_map = (int *)malloc(sizeof(int) * nprim);
				if (bm->a_map == NULL) {
					rt = -1;
					goto err_return;
				}
				for(j=0; j < nprim; j++) { bm->a_map[j] = -1; }
				bm->a_num = nprim;
			}
			break;
		case SYM_USERS:		/* users */
			bm->u_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->u_map == NULL){
				rt = -1;
				goto err_return;
			}
			bm->u_num = nprim;
			break;
		case SYM_BOOLS:		/* conditional booleans */
			bm->bool_map = (int *)malloc(sizeof(int) * nprim);
			if(bm->bool_map == NULL){
				rt = -1;
				goto err_return;
			}
			bm->bool_num = nprim;
			break;
		case SYM_SENS:		/* MLS Sensitivities */
			bm->sens_map = (int *)malloc(sizeof(int) * nprim);
			if (bm->sens_map == NULL) {
				rt = -1;
				goto err_return;
			}
			bm->sens_num = nprim;
			break;
		case SYM_CATS:		/* MLS Categories */
			break;
		default:	/* shouldn't get here */
			assert(FALSE);
			rt = -1; 
			goto err_return;
			break;
		}

		for (j = 0; j < nel; j++) {
			switch (i) {
			case SYM_COMMONS:	/* common permissions */
				rt = load_common_perm(fb, fp, bm, opts, policy);
				if(rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case SYM_CLASSES:	/* object classes */
				rt = load_class(fb, fp, bm, opts, policy);
				if(rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case SYM_ROLES:		/* roles */
				rt = load_role(fb, fp, bm, opts, policy);
				if(rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case SYM_TYPES:		/* types */
				rt = load_type(fb, fp, bm, opts, policy);
				if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case SYM_USERS:		/* users */
				rt = load_user(fb, fp, bm, opts, policy);
				if(rt != 0) goto err_return;
				break;
			case SYM_BOOLS:		/* conditional booleans */
				rt = load_bool(fb, fp, bm, opts, policy);
				if(rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) goto err_return;
				break;
			case SYM_SENS:		/* MLS sensitivies */
				rt = load_mls_sens(fb, fp, bm, opts, policy);
				if(rt < 0) goto err_return;
				break;
			case SYM_CATS:		/* MLS categories */
				rt = load_mls_cats(fb, fp, bm, opts, policy);
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
	rt = load_role_trans(fb, fp, bm, opts, policy);
	if(rt != 0) 
		return rt;

	/* role allow */
	rt = load_role_allow(fb, fp, bm, opts, policy);
	if(rt != 0) 
		return rt;

	/* object contexts */
	for (i=0; i < num_ocons; i++) {
		switch (i) {
		case OCON_ISID:
			rt = load_initial_sids(fb, fp, bm, opts, policy);
			if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) return rt;
			break;
		case OCON_FS:
			rt = skip_ocon_fs(fb, fp, bm, opts, policy);
			if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) return rt;
			break;
		case OCON_PORT:
			rt = load_ocon_port(fb, fp, bm, opts, policy);
			if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) return rt;
			break;
		case OCON_NETIF:
			rt = load_ocon_netif(fb, fp, bm, opts, policy);
			if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) return rt;
			break;
		case OCON_NODE:
			rt = load_ocon_node(fb, fp, bm, opts, policy);
			if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) return rt;
			break;
		case OCON_FSUSE:
			rt = load_ocon_fsuse(fb, fp, bm, opts, policy);
			if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) return rt;
			break;
		case OCON_NODE6:
			rt = load_ocon_node6(fb, fp, bm, opts, policy);
			if (rt < 0 && rt != LOAD_SUCCESS_NO_SAVE) return rt;
			break;
		default:
			assert(FALSE);
			return -1;
		}
	}

	/* genfs contexts */
	if (policy->version >= POL_VER_19) {
		rt = load_genfs_contexts(fb, fp, bm, opts, policy);
		if (rt < 0) return fb->err;
	}

	/* mls range_trans */
	if (policy->version >= POL_VER_19) {
		rt = load_range_trans(fb, fp, bm, opts, policy);
		if (rt < 0) return fb->err;
	}

	/* store the dominance */
	if (policy->version >= POL_VER_19) {
		policy->mls_dominance = (int*)malloc(policy->num_sensitivities * sizeof(int));
		if (!policy->mls_dominance) {
			fprintf(stderr, "Error: Out of memory\n");
			return -1;
		}
		/* we already loaded the sensitivies */
		assert(policy->num_sensitivities == bm->sens_num);
		for (i = 0; i < bm->sens_num; i++) {
			policy->mls_dominance[i] = bm->sens_map[i];
		}
	}
	
	/* type_attr_map */
	if (policy->version >= POL_VER_20) { 
		rt = load_type_attr_map(fb, fp, bm, opts, policy);
		if (rt < 0) { return fb->err; }
	}

	if (mls_config) {
		/* post-process the users sensitivities because we didn't have the mappings
		 * when we loaded the users */
		for (i = 0; i < policy->num_users; i++) {
			/* default level sens */
			tmp = policy->users[i].dflt_level->sensitivity;
			policy->users[i].dflt_level->sensitivity = bm->sens_map[tmp-1];
			
			/* range sens low */
			tmp = policy->users[i].range->low->sensitivity;
			policy->users[i].range->low->sensitivity = bm->sens_map[tmp-1];
			
			/* optional range sens high */
			if (policy->users[i].range->low != policy->users[i].range->high) {
				tmp = policy->users[i].range->high->sensitivity;
				policy->users[i].range->high->sensitivity = bm->sens_map[tmp-1];
			}
		}
	}

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

	ubuf = le32_to_cpu(ubuf);
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
	buf[0] = le32_to_cpu(buf[0]);
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

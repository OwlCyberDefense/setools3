/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * Read buffering 
 */

#ifndef _APOLICY_BINPOL_FBUF_H_
#define _APOLICY_BINPOL_FBUF_H_

#include <assert.h>
#include <stdio.h>

/* buffer for reading from file */
typedef struct fbuf {
	char 	*buf;
	size_t 	sz;
	int	err;
} ap_fbuf_t;

static inline void *ap_read_fbuf(ap_fbuf_t *fb, size_t bytes,  FILE *fp)
{
	size_t sz;
	
	assert(fb != NULL && fp != NULL);
	assert(!(fb->sz > 0 && fb->buf == NULL));
	
	if(fb->sz == 0) {
		fb->buf = (unsigned char *)malloc(bytes + 1);
		fb->sz = bytes + 1;
	}
	else if(bytes+1 > fb->sz) {
		fb->buf = (unsigned char *)realloc(fb->buf, bytes+1);
		fb->sz = bytes + 1;
	}

	if(fb->buf == NULL) {
		fb->err = -1;
		return NULL;
	}
	
	sz = fread(fb->buf, bytes, 1, fp);
	if(sz != 1) {
		fb->err = -3;
		return NULL;
	}
	fb->err = 0;
	return fb->buf;
}


int ap_init_fbuf(ap_fbuf_t **fb);
void ap_free_fbuf(ap_fbuf_t **fb);

#endif




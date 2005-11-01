/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * Read buffering 
 *
 */

#include <assert.h>
#include <stdio.h>
#include <malloc.h>
#include "fbuf.h"

int ap_init_fbuf(ap_fbuf_t **fb)
{
	if(fb == NULL)
		return -1;
	*fb = (ap_fbuf_t *)malloc(sizeof(ap_fbuf_t));
	if(*fb == NULL)
		return -1;
	(*fb)->buf = NULL;
	(*fb)->sz = 0;
	(*fb)->err = 0;
	return 0;
}

void ap_free_fbuf(ap_fbuf_t **fb)
{
	if(*fb == NULL)
		return;
	if((*fb)->sz > 0 && (*fb)->buf != NULL)
		free((*fb)->buf);
	free(*fb);
	return;
}



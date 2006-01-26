/* Copyright (C) 2001-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* config.c
 *
 * This is a horrible hack to get around using autoconf to set 
 * the char* pointer size in config.h
 * 
 */

#include <stdio.h>

int main(void)
{
	printf("#define SQLITE_PTR_SZ %d\n", sizeof(char*));
	return 0;
}

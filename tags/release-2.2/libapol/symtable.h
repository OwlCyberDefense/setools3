/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jtang@tresys.com 
 */

#ifndef _SYMTABLE_H_
#define _SYMTABLE_H_

#include "util.h"

typedef struct symbol {
    char * name;
    llist_t *value;
} symbol_t;

symbol_t *get_symbol (const char * const symbol_name);
symbol_t *new_symbol (char * const symbol_name);

#endif

/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jtang@tresys.com 
 */

/* A simple symbol table implemented as a linked list.  Nothing to see
 * here, carry on.
 */


#include <stdlib.h>
#include <string.h>

#include "symtable.h"
#include "util.h"

static llist_t *symtable = NULL;


/* Retrieves a symbol from the symbol table.  If it does not exist
   return NULL. */
symbol_t *get_symbol (const char * const symbol_name) {
    llist_node_t *node_ptr;
    if (symtable == NULL) {
        return NULL;
    }
    node_ptr = symtable->head;
    while (node_ptr != NULL) {
        symbol_t *sym = (symbol_t *) node_ptr->data;
        if (sym != NULL && strcmp (sym->name, symbol_name) == 0) {
            return sym;
        }
        node_ptr = node_ptr->next;
    }
    return NULL;
}


/* Adds a symbol to the symbol table without checking for duplicates.
   Afterwards returns a pointer to that symbol.  */
symbol_t *new_symbol (char * const symbol_name) {
    symbol_t *sym;
    if ((sym = malloc (sizeof (*sym))) == NULL) {
        return NULL;
    }
    if ((sym->name = strdup (symbol_name)) == NULL) {
        return NULL;
    }
    sym->value = ll_new ();
    if (symtable == NULL) {
        if ((symtable = ll_new ()) == NULL) {
            return NULL;
        }
    }
    (void) ll_append_data (symtable, sym);
    return sym;
}

/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 */

#ifndef CUSTOM_FILTER_WINDOW_H
#define CUSTOM_FILTER_WINDOW_H

enum filter_items_t {
	SRC_TYPES_FILTER,
	TGT_TYPES_FILTER,
	OBJECTS_FILTER
};

enum {
	ITEM_COLUMN, 
	N_COLUMNS
};

int custom_window_create(enum filter_items_t which_filter);

#endif

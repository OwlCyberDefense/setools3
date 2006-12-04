/* Copyright (C) 2004-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: January 22, 2004
 */

#include "seaudit_callback.h"
#include "seaudit.h"
#include <gtk/gtk.h>
#include <glade/glade.h>
#include <stdlib.h>

extern seaudit_t *seaudit_app;

static gint callback_compare(gconstpointer a, gconstpointer b);
static void seaudit_callback_signal_emit_1(gpointer data, gpointer user_data);
static void free_elem_data(gpointer data, gpointer user_data);

/* Register a callback on an event signal */
int seaudit_callback_register(seaudit_callback_t function, void *user_data, unsigned int type)
{
	registered_callback_t *callback = NULL;

	callback = (registered_callback_t *) malloc(sizeof(registered_callback_t));
	if (!callback)
		return -1;
	callback->function = function;
	callback->user_data = user_data;
	callback->type = type;
	seaudit_app->callbacks = g_list_append(seaudit_app->callbacks, callback);
	return 0;
}

/* we need to be able to remove these callbacks for example, when a window
 * is destroyed and no longer exists. */
void seaudit_callback_remove(seaudit_callback_t function, void *user_data, unsigned int type)
{
	GList *elem;
	registered_callback_t callback;

	callback.function = function;
	callback.user_data = user_data;
	callback.type = type;
	elem = g_list_find_custom(seaudit_app->callbacks, &callback, &callback_compare);
	if (elem == NULL)
		return;
	seaudit_app->callbacks = g_list_remove_link(seaudit_app->callbacks, elem);
	free_elem_data(elem->data, NULL);
	g_list_free_1(elem);
	return;
}

/* on exit of main program we can make sure all registered callbacks are removed
 * regardless of whether the caller removed them correctly. */
void seaudit_callbacks_free(void)
{
	g_list_foreach(seaudit_app->callbacks, &free_elem_data, NULL);
	g_list_free(seaudit_app->callbacks);
	seaudit_app->callbacks = NULL;
	return;
}

/* the signal emit function executes each function registered with 
 * seaudit_callback_register() */
void seaudit_callback_signal_emit(unsigned int type)
{
	g_list_foreach(seaudit_app->callbacks, &seaudit_callback_signal_emit_1, &type);
	return;
}

/*
 * Helper functions for registered_callback_t
 *
 */
static gint callback_compare(gconstpointer a, gconstpointer b)
{
	/* Order in the list does not matter, we just need to be able to know if
	 * two items are equal.  So if they are not equal, a is greater that b. */
	registered_callback_t *ca = (registered_callback_t *) a;
	registered_callback_t *cb = (registered_callback_t *) b;

	if (ca->function == cb->function && ca->user_data == cb->user_data && ca->type == cb->type)
		return 0;
	else
		return 1;
}

static void free_elem_data(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *) data;
	if (callback)
		free(callback);
	return;
}

static void seaudit_callback_signal_emit_1(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *) data;
	unsigned int type = *(unsigned int *)user_data;
	if (callback->type == type) {
		callback->function(callback->user_data);
	}
	return;
}

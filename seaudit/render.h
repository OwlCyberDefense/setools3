/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * October 10, 2003
 * 
 * render.h
 */

#include "auditlog.h"

#ifndef LIBSEAUDIT_RENDER_H
#define LIBSEAUDIT_RENDER_H

int get_rendered_avc_data(msg_t *msg, char *str, const int avc_field);

#endif

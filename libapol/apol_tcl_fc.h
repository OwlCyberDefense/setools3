 /* Copyright (C) 2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include <tcl.h>

#ifndef AP_TCL_FC_H
#define AP_TCL_FC_H

#ifdef LIBSEFS
#include "../libsefs/fsdata.h"

extern sefs_filesystem_db_t *fsdata;

#endif

int ap_tcl_fc_init(Tcl_Interp *interp);

#endif

 /* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* Test program for libseuser
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tcl.h>
#include <tk.h>
#include <assert.h>
/* libseuser */
#include "../seuser_tcl.h"
#include "../seuser_db.h"
/* apol lib */
#include "../../libapol/policy.h"
#include "../../libapol/apol_tcl.h"
#include "../../libapol/util.h"



int menu() {
	printf("\nSelect a command:\n");
	printf("0)  list system users\n");
	printf("1)  list system users with user type\n");
	printf("2)  list system groups\n");
	printf("\n");
	printf("v)  show libseuser verion\n");
	printf("m)  display menu\n");
	printf("q)  quit\n");
	return 0;
}

int main(int argc, char *argv[])
{
	int i, rt;
	int ac, cnt;
	char *av[2], **vals, *result;
	char ans[81];
	Tcl_Interp *interp;

	interp = Tcl_CreateInterp();
	av[0] = NULL;
	ac =1;
	if(Seuser_InitUserdb(NULL,interp,ac,av) != TCL_OK) {
		fprintf(stderr, Tcl_GetStringResult(interp));
		fprintf(stderr, "\n\n");
	}	
	
	
	/* test menu here */
	
	menu();
	for(;;) {
		printf("\nCommand (\'m\' for menu):  ");
		fgets(ans, sizeof(ans), stdin);	
		switch(ans[0]) {

		case '0':
			ac = 1;
			if(Seuser_GetSysUsers(NULL, interp, ac, av) != TCL_OK) {
				fprintf(stderr, Tcl_GetStringResult(interp));
				fprintf(stderr, "\n\n");
				break;
			}
			result = (char*)Tcl_GetStringResult(interp);
			rt = Tcl_SplitList(interp, result, &cnt, (const char***)(&vals));
			if(rt != TCL_OK) {
				Tcl_Free((char *) vals);
				fprintf(stderr, Tcl_GetStringResult(interp));
				fprintf(stderr, "\n\n");
				break;
			}
			printf("\nThere are %d SYSTEM USERS\n", cnt);
			for(i = 0; i < cnt; i++) {
				printf("   %s\n", vals[i]);
			}
			Tcl_Free((char *) vals);
			break;
		case '1':
			ac = 2;
			av[1] = "1"; /* indicate we want optional type info */
			if(Seuser_GetSysUsers(NULL, interp, ac, av) != TCL_OK) {
				fprintf(stderr, Tcl_GetStringResult(interp));
				fprintf(stderr, "\n\n");
				break;
			}
			result = (char*)Tcl_GetStringResult(interp);
			rt = Tcl_SplitList(interp, result, &cnt, (const char***)(&vals));
			if(rt != TCL_OK) {
				Tcl_Free((char *) vals);
				fprintf(stderr, Tcl_GetStringResult(interp));
				fprintf(stderr, "\n\n");
				break;
			}
			printf("\nThere are %d SYSTEM USERS\n", cnt/2);
			for(i = 0; i < cnt; i++) {
				printf("   %15s\t", vals[i]);
				i++;
				printf("%s\n", vals[i]);
			}
			Tcl_Free((char *) vals);
			break;
		case '2': 
			ac = 1;
			if(Seuser_GetSysGroups(NULL, interp, ac, av) != TCL_OK) {
				fprintf(stderr, Tcl_GetStringResult(interp));
				fprintf(stderr, "\n\n");
				break;
			}
			result = (char*)Tcl_GetStringResult(interp);
			rt = Tcl_SplitList(interp, result, &cnt, (const char***)(&vals));
			if(rt != TCL_OK) {
				Tcl_Free((char *) vals);
				fprintf(stderr, Tcl_GetStringResult(interp));
				fprintf(stderr, "\n\n");
				break;
			}
			printf("\nThere are %d system GROUPS\n", cnt);
			for(i = 0; i < cnt; i++) {
				printf("   %s\n", vals[i]);
			}
			Tcl_Free((char *) vals);
			break;
		case 'v':
			printf("\n%s\n", libseuser_get_version());
			break;
		case 'q':
			Seuser_CloseDatabase(NULL, interp, ac, av);
			exit(0);
			break;
		default:
			printf("\nInvalid choice\n");
			menu();
			break;
		}
	}
}



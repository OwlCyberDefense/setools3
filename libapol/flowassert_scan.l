/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jtang@tresys.com 
 */
 
%{
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "flowassert.h"
#include "flowassert_parse.h"

extern int fileno (FILE *);

int flowerror(char *msg);
void flowwarn(char *format, ...);

static void flowstrdup (void);
unsigned long flowassert_lineno = 1;

#define YY_NO_UNPUT
%}

%array
%option noyywrap

identifier [A-Za-z][A-Za-z0-9_]*
number [0-9]+

%%

#[^\n]*                  { /* delete comments */ }
(noflow)|(NOFLOW)        { return (NOFLOW); }
(mustflow)|(MUSTFLOW)    { return (MUSTFLOW); }
(onlyflow)|(ONLYFLOW)    { return (ONLYFLOW); }
{identifier}             { flowstrdup (); return (IDENTIFIER); }
\${identifier}           { flowstrdup (); return (VARNAME); }
{number}                 { flowlval.i = atoi (flowtext); return (NUMBER); }
[ \t\f]+		 { /* delete whitespace */ }
\n			 { /* delete whitespace */ flowassert_lineno++; }
[:;\{\}*=-]              { return (flowtext [0]); } 
.                        { (void) flowwarn ("unrecognized character");}

%%

/* yyerror() specifically for the flowassert tool. */
int flowerror (char *msg) {
        /*    flowwarn ("%s on token `%s'", msg, flowtext); */
        flowassert_add_error_result (FLOW_ASSERT_SYNTAX_ERROR);
        return -1;
}

/* Displays a warning to standard error regarding a problem with the
   assertion file.  Also displays the line on which the warning
   occurred. */
void flowwarn (char *format, ...) {
        /*
          va_list ap;
          (void) fprintf (stderr, "line %ld: ", flowassert_lineno);
          va_start (ap, format);
          (void) vfprintf (stderr, format, ap);
          va_end (ap);
          (void) fprintf (stderr, "\n");
        */
        flowassert_add_error_result (FLOW_ASSERT_SYNTAX_ERROR);    
}

/* strdup()s flowtext (really yytext) to flowlval.s (really
   yylval.s). */
static void flowstrdup (void) {
        if ((flowlval.s = strdup (flowtext)) == NULL) {
                (void) fprintf (stderr, "out of memory in flowstrdup\n");
                exit (-1);
        }
}

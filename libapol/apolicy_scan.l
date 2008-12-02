/* Copyright (C) 2001-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* This file largley copied directly from SE Linux source */

%{
#include "y.tab.h"
unsigned long policydb_lineno = 1;
unsigned int policydb_errors = 0;
int yyerror(char *msg);
int yywarn(char *msg);
#define YY_NO_UNPUT
%}
%array
letter  [A-Za-z]
digit   [0-9]
hexval	[0-9A-Fa-f]
%%
CLONE |
clone				{ return(CLONE); }
COMMON |
common				{ return(COMMON); }
CLASS |
class				{ return(CLASS); }
CONSTRAIN |
constrain			{ return(CONSTRAIN); }
INHERITS |
inherits			{ return(INHERITS); }
SID |
sid				{ return(SID); }
ROLE |
role				{ return(ROLE); }
ROLES |
roles				{ return(ROLES); }
TYPES |
types				{ return(TYPES); }
TYPEATTRIBUTE |
typeattribute			{ return(TYPEATTRIBUTE); }
TYPEALIAS |
typealias			{ return(TYPEALIAS); }
BOOL |
bool                            { return(BOOL); }
IF |
if    		                { return(IF); }
ELSE |
else  				{ return(ELSE); }
TYPE |
type				{ return(TYPE); }
ALIAS |
alias				{ return(ALIAS); }
ATTRIBUTE |
attribute			{ return(ATTRIBUTE); }
TYPE_TRANSITION |
type_transition			{ return(TYPE_TRANSITION); }
TYPE_MEMBER |
type_member			{ return(TYPE_MEMBER); }
TYPE_CHANGE |
type_change			{ return(TYPE_CHANGE); }
ROLE_TRANSITION |
role_transition			{ return(ROLE_TRANSITION); }
SENSITIVITY |
sensitivity			{ return(SENSITIVITY); }
DOMINANCE |
dominance			{ return(DOMINANCE); }
CATEGORY |
category			{ return(CATEGORY); }
LEVEL |
level				{ return(LEVEL); }
RANGES |
ranges				{ return(RANGES); }
USER |
user				{ return(USER); }
NEVERALLOW |
neverallow		        { return(NEVERALLOW); }
ALLOW |
allow			        { return(ALLOW); }
AUDITALLOW |
auditallow		        { return(AUDITALLOW); }
AUDITDENY |
auditdeny		        { return(AUDITDENY); }
DONTAUDIT |
dontaudit 			{ return(DONTAUDIT); }
SOURCE |
source			        { return(SOURCE); }
TARGET |
target			        { return(TARGET); }
SAMEUSER |
sameuser			{ return(SAMEUSER);}
OR |
or     			        { return(OR);}
AND |
and				{ return(AND);}
NOT |
not				{ return(NOT);}
xor |
XOR                             { return(XOR); }
eq |
EQ				{ return(EQUALS);}
true |
TRUE                            { return(CTRUE); } 
false |
FALSE                           { return(CFALSE); } 
dom |
DOM				{ return(DOM);}
domby |
DOMBY				{ return(DOMBY);}
INCOMP |
incomp				{ return(INCOMP);}
fscon |
FSCON                           { return(FSCON);}
portcon |
PORTCON                        { return(PORTCON);}
netifcon |                     
NETIFCON                       { return(NETIFCON);}
nodecon |                     
NODECON                       { return(NODECON);}
fs_use_psid |
FS_USE_PSID                     {return(FSUSEPSID);}
fs_use_task |
FS_USE_TASK                     {return(FSUSETASK);}
fs_use_trans |
FS_USE_TRANS                    {return(FSUSETRANS);}
fs_use_xattr |
FS_USE_XATTR                     {return(FSUSEXATTR);}
genfscon |
GENFSCON                        { return(GENFSCON);}
r1 |
R1				{ return(R1); }
r2 |
R2				{ return(R2); }
u1 |
U1				{ return(U1); }
u2 |
U2				{ return(U2); }
t1 |
T1				{ return(T1); }
t2 |
T2				{ return(T2); }
"/"({letter}|{digit}|_|"."|"-"|"/")*	{ return(PATH); }
{letter}({letter}|{digit}|_|".")*("*")?	{ return(IDENTIFIER); }
{digit}{digit}*                 { return(NUMBER); }
{hexval}{0,4}":"{hexval}{0,4}":"({hexval}|":"|".")*	{ return(IPV6_ADDR); }
#[^\n]*                         { /* delete comments */ }
[ \t\f]+			{ /* delete whitespace */ }
\n				{ /* delete whitespace */ policydb_lineno++; }
"==" 				{ return(EQUALS); }
"!="				{ return (NOTEQUAL); }
"&&"				{ return (AND); }
"||"				{ return (OR); }
"!"				{ return (NOT); }
"^"                             { return (XOR); }
"," |
":" |
";" |
"(" | 
")" |
"{" | 
"}" |
"[" |
"-" |
"." |
"]" |
"~" |
"*" 				{ return(yytext[0]); } 
.                               { yywarn("unrecognized character");}
%%
int yyerror(char *msg)
{
	fprintf(stderr, "\nerror in the statement ending on line %ld (token '%s'): %s\n\n", policydb_lineno, yytext, msg);
	policydb_errors++;
	return -1;
}

int yywarn(char *msg)
{
	fprintf(stderr, "\nwarning about the statement ending on line %ld (token '%s'): %s\n\n", policydb_lineno, yytext, msg);
	return 0;
}

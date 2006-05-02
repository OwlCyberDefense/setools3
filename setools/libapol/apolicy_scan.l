/* Copyright (C) 2001-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* This file largley copied directly from SE Linux source */

%option stack
%option nodefault

%{

#include "y.tab.h"
unsigned long policydb_lineno = 1;
unsigned int policydb_errors = 0;

int yyerror(char *msg);
int yywarn(char *msg);
int yystate(void);
int yyleave_state(void);
int yyenter_ignore(void);
int yyenter_accept(void);
int yyenter_decl(void);
int yyenter_require(void);
int yyenter_optonly(void);
int yybegin_initial(void);
int yybegin_optonly(void);
int yyis_accept(void); 
int yyis_decl(void); 

#define YY_NO_UNPUT
extern int pass;

%}

%x IGNORE
%x DECL
%x REQ
%x OPTONLY
%x NEEDBRACE
%x IGGYREQ

%array
letter  [A-Za-z]
digit   [0-9]
hexval	[0-9A-Fa-f]
id {letter}({letter}|{digit}|_|".")*("*")?

%%
CLONE|clone				{ return(CLONE); }
COMMON|common				{ return(COMMON); }
CLASS|class				{ return(CLASS); }
CONSTRAIN|constrain			{ return(CONSTRAIN); }
VALIDATETRANS|validatetrans		{ return(VALIDATETRANS); }
MLSCONSTRAIN|mlsconstrain		{ return(MLSCONSTRAIN); }
MLSVALIDATETRANS|mlsvalidatetrans	{ return(MLSVALIDATETRANS); }
INHERITS|inherits			{ return(INHERITS); }
SID|sid					{ return(SID); }

<INITIAL,DECL>{
ROLE|role				{ return(ROLE); }
TYPES|types				{ return(TYPES); }
BOOL|bool                            	{ return(BOOL); }
true|TRUE                            	{ return(CTRUE); } 
false|FALSE                           	{ return(CFALSE); } 
TYPE|type				{ return(TYPE); }
ALIAS|alias				{ return(ALIAS); }
TYPEALIAS|typealias			{ return(TYPEALIAS); }
TYPEATTRIBUTE|typeattribute		{ return(TYPEATTRIBUTE); }
ATTRIBUTE|attribute			{ return(ATTRIBUTE); }
USER|user				{ return(USER); }
ROLES|roles				{ return(ROLES); }
LEVEL|level				{ return(LEVEL); }
RANGE|range				{ return(RANGE); }
REQUIRE|require				{ yy_push_state(NEEDBRACE); return(REQUIRE); }
TYPE_TRANSITION|type_transition		{ return(TYPE_TRANSITION); }
TYPE_MEMBER|type_member			{ return(TYPE_MEMBER); }
TYPE_CHANGE|type_change			{ return(TYPE_CHANGE); }
ROLE_TRANSITION|role_transition		{ return(ROLE_TRANSITION); }
RANGE_TRANSITION|range_transition	{ return(RANGE_TRANSITION); }
NEVERALLOW|neverallow		        { return(NEVERALLOW); }
ALLOW|allow			        { return(ALLOW); }
AUDITALLOW|auditallow		        { return(AUDITALLOW); }
AUDITDENY|auditdeny		        { return(AUDITDENY); }
DONTAUDIT|dontaudit 			{ return(DONTAUDIT); }
OR|or     			        { return(OR); }
AND|and					{ return(AND); }
NOT|not					{ return(NOT); }
xor|XOR         	                { return(XOR); }
"&&"					{ return(AND); }
"||"					{ return(OR); }
"!"					{ return(NOT); }
"^"                             	{ return(XOR); }
}

<DECL>IF|if 				{ yy_push_state(NEEDBRACE); return(DECLIF); }
IF|if    		                { return(IF); }
<*>ELSE|else  				{ yy_push_state(NEEDBRACE); return(ELSE); }
<*>OPTIONAL|optional			{ yy_push_state(NEEDBRACE); return(OPTIONAL); }
SENSITIVITY|sensitivity			{ return(SENSITIVITY); }
DOMINANCE|dominance			{ return(DOMINANCE); }
CATEGORY|category			{ return(CATEGORY); }
SOURCE|source			        { return(SOURCE); }
TARGET|target			        { return(TARGET); }
SAMEUSER|sameuser			{ return(SAMEUSER); }
eq|EQ					{ return(EQUALS); }
dom|DOM					{ return(DOM); }
domby|DOMBY				{ return(DOMBY); }
INCOMP|incomp				{ return(INCOMP); }
fscon|FSCON                           	{ return(FSCON); }
portcon|PORTCON                        	{ return(PORTCON); }
netifcon|NETIFCON                       { return(NETIFCON); }
nodecon|NODECON                       	{ return(NODECON); }
fs_use_psid|FS_USE_PSID                 { return(FSUSEPSID); }
fs_use_task|FS_USE_TASK                 { return(FSUSETASK); }
fs_use_trans|FS_USE_TRANS               { return(FSUSETRANS); }
fs_use_xattr|FS_USE_XATTR               { return(FSUSEXATTR); }
genfscon|GENFSCON                       { return(GENFSCON); }
r1|R1					{ return(R1); }
r2|R2					{ return(R2); }
u1|U1					{ return(U1); }
u2|U2					{ return(U2); }
t1|T1					{ return(T1); }
t2|T2					{ return(T2); }
r3|R3					{ return(R3); }
u3|U3					{ return(U3); }
t3|T3					{ return(T3); }
l1|L1					{ return(L1); }
l2|L2					{ return(L2); }
h1|H1					{ return(H1); }
h2|H2					{ return(H2); }
"/"({letter}|{digit}|_|"."|"-"|"/")*	{ return(PATH); }
{id}					{ return(IDENTIFIER); }
{digit}{digit}*                 	{ return(NUMBER); }
{hexval}{0,4}":"{hexval}{0,4}":"({hexval}|":"|".")*	{ return(IPV6_ADDR); }
<*>#[^\n]*                         	{ /* delete comments */ }
<*>[ \t\f]+				{ /* delete whitespace */ }
<*>\n					{ /* delete whitespace */ policydb_lineno++; }
"==" 					{ return(EQUALS); }
"!="					{ return(NOTEQUAL); }

<DECL,INITIAL>{
[,:;()\[\]\-.~*] 			{ return yytext[0]; } 
{id} 					{ return(IDENTIFIER); }
}

<NEEDBRACE>\{ 				{ return'{'; }
<*>\{ 					{ yy_push_state(YYSTATE); if(YYSTATE!=IGNORE && YYSTATE!=OPTONLY) return '{'; }
<*>\} 					{ int oldstate=YYSTATE; yy_pop_state(); if ((oldstate!=IGNORE && oldstate!=OPTONLY) || YYSTATE==NEEDBRACE) return '}'; }
.                               	{ yywarn("unrecognized character"); }

<REQ>{
USER|user				{ return(USER); }
ROLE|role 				{ return(ROLE); }
TYPE|type 				{ return(TYPE); }
BOOL|bool 				{ return(BOOL); }
ATTRIBUTE|attribute 			{ return(ATTRIBUTE); }
CLASS|class 				{ return(CLASS); }
{id} 					{ return(IDENTIFIER); }
. 					{ return yytext[0]; }
}

<REQ,DECL,OPTONLY,IGNORE,IGGYREQ,NEEDBRACE>(({letter}|_)+|.) ;
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

int yystate(void)
{
	return YYSTATE;
}

int yyleave_state(void)
{
	yy_pop_state();
	return 0;
}

int yyenter_accept(void)
{
	yy_push_state(INITIAL);
	return 0;
}

int yybegin_initial(void)
{
	BEGIN(INITIAL);
	return 0;
}

int yyenter_ignore(void)
{
	yy_push_state(IGNORE);
	return 0;
}

int yyenter_decl(void)
{
	yy_push_state(DECL);
	return 0;
}

int yyenter_require(void)
{
	yy_push_state(REQ);
	return 0;
}

int yyis_accept(void) 
{
	return YYSTATE==INITIAL;
}

int yyis_decl(void) 
{
	return YYSTATE==DECL;
}

int yybegin_optonly(void)
{
	BEGIN(OPTONLY);
	return 0;
}

int yyenter_optonly(void)
{
	yy_push_state(OPTONLY);
	return 0;
}


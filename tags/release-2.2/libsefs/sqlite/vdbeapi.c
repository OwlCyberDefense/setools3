/*
** 2004 May 26
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
**
** This file contains code use to implement APIs that are part of the
** VDBE.
*/
#include "sqliteInt.h"
#include "vdbeInt.h"

/**************************** sqlite3_value_  *******************************
** The following routines extract information from a Mem or sqlite3_value
** structure.
*/
const void *sqlite3_value_blob(sqlite3_value *pVal){
  Mem *p = (Mem*)pVal;
  if( p->flags & (MEM_Blob|MEM_Str) ){
    return p->z;
  }else{
    return sqlite3_value_text(pVal);
  }
}
int sqlite3_value_bytes(sqlite3_value *pVal){
  return sqlite3ValueBytes(pVal, SQLITE_UTF8);
}
int sqlite3_value_bytes16(sqlite3_value *pVal){
  return sqlite3ValueBytes(pVal, SQLITE_UTF16NATIVE);
}
double sqlite3_value_double(sqlite3_value *pVal){
  return sqlite3VdbeRealValue((Mem*)pVal);
}
int sqlite3_value_int(sqlite3_value *pVal){
  return sqlite3VdbeIntValue((Mem*)pVal);
}
sqlite_int64 sqlite3_value_int64(sqlite3_value *pVal){
  return sqlite3VdbeIntValue((Mem*)pVal);
}
const unsigned char *sqlite3_value_text(sqlite3_value *pVal){
  return (const char *)sqlite3ValueText(pVal, SQLITE_UTF8);
}
const void *sqlite3_value_text16(sqlite3_value* pVal){
  return sqlite3ValueText(pVal, SQLITE_UTF16NATIVE);
}
const void *sqlite3_value_text16be(sqlite3_value *pVal){
  return sqlite3ValueText(pVal, SQLITE_UTF16BE);
}
const void *sqlite3_value_text16le(sqlite3_value *pVal){
  return sqlite3ValueText(pVal, SQLITE_UTF16LE);
}
int sqlite3_value_type(sqlite3_value* pVal){
  return pVal->type;
}

/**************************** sqlite3_result_  *******************************
** The following routines are used by user-defined functions to specify
** the function result.
*/
void sqlite3_result_blob(
  sqlite3_context *pCtx, 
  const void *z, 
  int n, 
  void (*xDel)(void *)
){
  assert( n>0 );
  sqlite3VdbeMemSetStr(&pCtx->s, z, n, 0, xDel);
}
void sqlite3_result_double(sqlite3_context *pCtx, double rVal){
  sqlite3VdbeMemSetDouble(&pCtx->s, rVal);
}
void sqlite3_result_error(sqlite3_context *pCtx, const char *z, int n){
  pCtx->isError = 1;
  sqlite3VdbeMemSetStr(&pCtx->s, z, n, SQLITE_UTF8, SQLITE_TRANSIENT);
}
void sqlite3_result_error16(sqlite3_context *pCtx, const void *z, int n){
  pCtx->isError = 1;
  sqlite3VdbeMemSetStr(&pCtx->s, z, n, SQLITE_UTF16NATIVE, SQLITE_TRANSIENT);
}
void sqlite3_result_int(sqlite3_context *pCtx, int iVal){
  sqlite3VdbeMemSetInt64(&pCtx->s, (i64)iVal);
}
void sqlite3_result_int64(sqlite3_context *pCtx, i64 iVal){
  sqlite3VdbeMemSetInt64(&pCtx->s, iVal);
}
void sqlite3_result_null(sqlite3_context *pCtx){
  sqlite3VdbeMemSetNull(&pCtx->s);
}
void sqlite3_result_text(
  sqlite3_context *pCtx, 
  const char *z, 
  int n,
  void (*xDel)(void *)
){
  sqlite3VdbeMemSetStr(&pCtx->s, z, n, SQLITE_UTF8, xDel);
}
void sqlite3_result_text16(
  sqlite3_context *pCtx, 
  const void *z, 
  int n, 
  void (*xDel)(void *)
){
  sqlite3VdbeMemSetStr(&pCtx->s, z, n, SQLITE_UTF16NATIVE, xDel);
}
void sqlite3_result_text16be(
  sqlite3_context *pCtx, 
  const void *z, 
  int n, 
  void (*xDel)(void *)
){
  sqlite3VdbeMemSetStr(&pCtx->s, z, n, SQLITE_UTF16BE, xDel);
}
void sqlite3_result_text16le(
  sqlite3_context *pCtx, 
  const void *z, 
  int n, 
  void (*xDel)(void *)
){
  sqlite3VdbeMemSetStr(&pCtx->s, z, n, SQLITE_UTF16LE, xDel);
}
void sqlite3_result_value(sqlite3_context *pCtx, sqlite3_value *pValue){
  sqlite3VdbeMemCopy(&pCtx->s, pValue);
}


/*
** Execute the statement pStmt, either until a row of data is ready, the
** statement is completely executed or an error occurs.
*/
int sqlite3_step(sqlite3_stmt *pStmt){
  Vdbe *p = (Vdbe*)pStmt;
  sqlite3 *db;
  int rc;

  if( p==0 || p->magic!=VDBE_MAGIC_RUN ){
    return SQLITE_MISUSE;
  }
  if( p->aborted ){
    return SQLITE_ABORT;
  }
  db = p->db;
  if( sqlite3SafetyOn(db) ){
    p->rc = SQLITE_MISUSE;
    return SQLITE_MISUSE;
  }
  if( p->pc<0 ){
    /* Invoke the trace callback if there is one
    */
    if( (db = p->db)->xTrace && !db->init.busy ){
      assert( p->nOp>0 );
      assert( p->aOp[p->nOp-1].opcode==OP_Noop );
      assert( p->aOp[p->nOp-1].p3!=0 );
      assert( p->aOp[p->nOp-1].p3type==P3_DYNAMIC );
      sqlite3SafetyOff(db);
      db->xTrace(db->pTraceArg, p->aOp[p->nOp-1].p3);
      if( sqlite3SafetyOn(db) ){
        p->rc = SQLITE_MISUSE;
        return SQLITE_MISUSE;
      }
    }

    /* Print a copy of SQL as it is executed if the SQL_TRACE pragma is turned
    ** on in debugging mode.
    */
#ifdef SQLITE_DEBUG
    if( (db->flags & SQLITE_SqlTrace)!=0 ){
      sqlite3DebugPrintf("SQL-trace: %s\n", p->aOp[p->nOp-1].p3);
    }
#endif /* SQLITE_DEBUG */

    db->activeVdbeCnt++;
    p->pc = 0;
  }
  if( p->explain ){
    rc = sqlite3VdbeList(p);
  }else{
    rc = sqlite3VdbeExec(p);
  }

  if( sqlite3SafetyOff(db) ){
    rc = SQLITE_MISUSE;
  }

  sqlite3Error(p->db, rc, p->zErrMsg);
  return rc;
}

/*
** Extract the user data from a sqlite3_context structure and return a
** pointer to it.
*/
void *sqlite3_user_data(sqlite3_context *p){
  assert( p && p->pFunc );
  return p->pFunc->pUserData;
}

/*
** Allocate or return the aggregate context for a user function.  A new
** context is allocated on the first call.  Subsequent calls return the
** same context that was returned on prior calls.
**
** This routine is defined here in vdbe.c because it depends on knowing
** the internals of the sqlite3_context structure which is only defined in
** this source file.
*/
void *sqlite3_aggregate_context(sqlite3_context *p, int nByte){
  assert( p && p->pFunc && p->pFunc->xStep );
  if( p->pAgg==0 ){
    if( nByte<=NBFS ){
      p->pAgg = (void*)p->s.z;
      memset(p->pAgg, 0, nByte);
    }else{
      p->pAgg = sqliteMalloc( nByte );
    }
  }
  return p->pAgg;
}

/*
** Return the auxilary data pointer, if any, for the iArg'th argument to
** the user-function defined by pCtx.
*/
void *sqlite3_get_auxdata(sqlite3_context *pCtx, int iArg){
  VdbeFunc *pVdbeFunc = pCtx->pVdbeFunc;
  if( !pVdbeFunc || iArg>=pVdbeFunc->nAux || iArg<0 ){
    return 0;
  }
  return pVdbeFunc->apAux[iArg].pAux;
}

/*
** Set the auxilary data pointer and delete function, for the iArg'th
** argument to the user-function defined by pCtx. Any previous value is
** deleted by calling the delete function specified when it was set.
*/
void sqlite3_set_auxdata(
  sqlite3_context *pCtx, 
  int iArg, 
  void *pAux, 
  void (*xDelete)(void*)
){
  struct AuxData *pAuxData;
  VdbeFunc *pVdbeFunc;
  if( iArg<0 ) return;

  pVdbeFunc = pCtx->pVdbeFunc;
  if( !pVdbeFunc || pVdbeFunc->nAux<=iArg ){
    int nMalloc = sizeof(VdbeFunc) + sizeof(struct AuxData)*iArg;
    pCtx->pVdbeFunc = pVdbeFunc = sqliteRealloc(pVdbeFunc, nMalloc);
    if( !pVdbeFunc ) return;
    memset(&pVdbeFunc->apAux[pVdbeFunc->nAux], 0, 
             sizeof(struct AuxData)*(iArg+1-pVdbeFunc->nAux));
    pVdbeFunc->nAux = iArg+1;
    pVdbeFunc->pFunc = pCtx->pFunc;
  }

  pAuxData = &pVdbeFunc->apAux[iArg];
  if( pAuxData->pAux && pAuxData->xDelete ){
    pAuxData->xDelete(pAuxData->pAux);
  }
  pAuxData->pAux = pAux;
  pAuxData->xDelete = xDelete;
}

/*
** Return the number of times the Step function of a aggregate has been 
** called.
**
** This routine is defined here in vdbe.c because it depends on knowing
** the internals of the sqlite3_context structure which is only defined in
** this source file.
*/
int sqlite3_aggregate_count(sqlite3_context *p){
  assert( p && p->pFunc && p->pFunc->xStep );
  return p->cnt;
}

/*
** Return the number of columns in the result set for the statement pStmt.
*/
int sqlite3_column_count(sqlite3_stmt *pStmt){
  Vdbe *pVm = (Vdbe *)pStmt;
  return pVm ? pVm->nResColumn : 0;
}

/*
** Return the number of values available from the current row of the
** currently executing statement pStmt.
*/
int sqlite3_data_count(sqlite3_stmt *pStmt){
  Vdbe *pVm = (Vdbe *)pStmt;
  if( pVm==0 || !pVm->resOnStack ) return 0;
  return pVm->nResColumn;
}


/*
** Check to see if column iCol of the given statement is valid.  If
** it is, return a pointer to the Mem for the value of that column.
** If iCol is not valid, return a pointer to a Mem which has a value
** of NULL.
*/
static Mem *columnMem(sqlite3_stmt *pStmt, int i){
  Vdbe *pVm = (Vdbe *)pStmt;
  int vals = sqlite3_data_count(pStmt);
  if( i>=vals || i<0 ){
    static Mem nullMem;
    if( nullMem.flags==0 ){ nullMem.flags = MEM_Null; }
    sqlite3Error(pVm->db, SQLITE_RANGE, 0);
    return &nullMem;
  }
  return &pVm->pTos[(1-vals)+i];
}

/**************************** sqlite3_column_  *******************************
** The following routines are used to access elements of the current row
** in the result set.
*/
const void *sqlite3_column_blob(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_blob( columnMem(pStmt,i) );
}
int sqlite3_column_bytes(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_bytes( columnMem(pStmt,i) );
}
int sqlite3_column_bytes16(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_bytes16( columnMem(pStmt,i) );
}
double sqlite3_column_double(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_double( columnMem(pStmt,i) );
}
int sqlite3_column_int(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_int( columnMem(pStmt,i) );
}
sqlite_int64 sqlite3_column_int64(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_int64( columnMem(pStmt,i) );
}
const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_text( columnMem(pStmt,i) );
}
const void *sqlite3_column_text16(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_text16( columnMem(pStmt,i) );
}
int sqlite3_column_type(sqlite3_stmt *pStmt, int i){
  return sqlite3_value_type( columnMem(pStmt,i) );
}

/*
** Convert the N-th element of pStmt->pColName[] into a string using
** xFunc() then return that string.  If N is out of range, return 0.
** If useType is 1, then use the second set of N elements (the datatype
** names) instead of the first set.
*/
static const void *columnName(
  sqlite3_stmt *pStmt,
  int N,
  const void *(*xFunc)(Mem*),
  int useType
){
  Vdbe *p = (Vdbe *)pStmt;
  int n = sqlite3_column_count(pStmt);

  if( p==0 || N>=n || N<0 ){
    return 0;
  }
  if( useType ){
    N += n;
  }
  return xFunc(&p->aColName[N]);
}


/*
** Return the name of the Nth column of the result set returned by SQL
** statement pStmt.
*/
const char *sqlite3_column_name(sqlite3_stmt *pStmt, int N){
  return columnName(pStmt, N, (const void*(*)(Mem*))sqlite3_value_text, 0);
}

/*
** Return the name of the 'i'th column of the result set of SQL statement
** pStmt, encoded as UTF-16.
*/
const void *sqlite3_column_name16(sqlite3_stmt *pStmt, int N){
  return columnName(pStmt, N, (const void*(*)(Mem*))sqlite3_value_text16, 0);
}

/*
** Return the column declaration type (if applicable) of the 'i'th column
** of the result set of SQL statement pStmt, encoded as UTF-8.
*/
const char *sqlite3_column_decltype(sqlite3_stmt *pStmt, int N){
  return columnName(pStmt, N, (const void*(*)(Mem*))sqlite3_value_text, 1);
}

/*
** Return the column declaration type (if applicable) of the 'i'th column
** of the result set of SQL statement pStmt, encoded as UTF-16.
*/
const void *sqlite3_column_decltype16(sqlite3_stmt *pStmt, int N){
  return columnName(pStmt, N, (const void*(*)(Mem*))sqlite3_value_text16, 1);
}

/******************************* sqlite3_bind_  ***************************
** 
** Routines used to attach values to wildcards in a compiled SQL statement.
*/
/*
** Unbind the value bound to variable i in virtual machine p. This is the 
** the same as binding a NULL value to the column. If the "i" parameter is
** out of range, then SQLITE_RANGE is returned. Othewise SQLITE_OK.
**
** The error code stored in database p->db is overwritten with the return
** value in any case.
*/
static int vdbeUnbind(Vdbe *p, int i){
  Mem *pVar;
  if( p==0 || p->magic!=VDBE_MAGIC_RUN || p->pc>=0 ){
    sqlite3Error(p->db, SQLITE_MISUSE, 0);
    return SQLITE_MISUSE;
  }
  if( i<1 || i>p->nVar ){
    sqlite3Error(p->db, SQLITE_RANGE, 0);
    return SQLITE_RANGE;
  }
  i--;
  pVar = &p->aVar[i];
  sqlite3VdbeMemRelease(pVar);
  pVar->flags = MEM_Null;
  sqlite3Error(p->db, SQLITE_OK, 0);
  return SQLITE_OK;
}

/*
** Bind a text or BLOB value.
*/
static int bindText(
  sqlite3_stmt *pStmt, 
  int i, 
  const void *zData, 
  int nData, 
  void (*xDel)(void*),
  int encoding
){
  Vdbe *p = (Vdbe *)pStmt;
  Mem *pVar;
  int rc;

  rc = vdbeUnbind(p, i);
  if( rc || zData==0 ){
    return rc;
  }
  pVar = &p->aVar[i-1];
  rc = sqlite3VdbeMemSetStr(pVar, zData, nData, encoding, xDel);
  if( rc ){
    return rc;
  }
  if( rc==SQLITE_OK && encoding!=0 ){
    rc = sqlite3VdbeChangeEncoding(pVar, p->db->enc);
  }
  return rc;
}


/*
** Bind a blob value to an SQL statement variable.
*/
int sqlite3_bind_blob(
  sqlite3_stmt *pStmt, 
  int i, 
  const void *zData, 
  int nData, 
  void (*xDel)(void*)
){
  return bindText(pStmt, i, zData, nData, xDel, 0);
}
int sqlite3_bind_double(sqlite3_stmt *pStmt, int i, double rValue){
  int rc;
  Vdbe *p = (Vdbe *)pStmt;
  rc = vdbeUnbind(p, i);
  if( rc==SQLITE_OK ){
    sqlite3VdbeMemSetDouble(&p->aVar[i-1], rValue);
  }
  return rc;
}
int sqlite3_bind_int(sqlite3_stmt *p, int i, int iValue){
  return sqlite3_bind_int64(p, i, (i64)iValue);
}
int sqlite3_bind_int64(sqlite3_stmt *pStmt, int i, sqlite_int64 iValue){
  int rc;
  Vdbe *p = (Vdbe *)pStmt;
  rc = vdbeUnbind(p, i);
  if( rc==SQLITE_OK ){
    sqlite3VdbeMemSetInt64(&p->aVar[i-1], iValue);
  }
  return rc;
}
int sqlite3_bind_null(sqlite3_stmt* p, int i){
  return vdbeUnbind((Vdbe *)p, i);
}
int sqlite3_bind_text( 
  sqlite3_stmt *pStmt, 
  int i, 
  const char *zData, 
  int nData, 
  void (*xDel)(void*)
){
  return bindText(pStmt, i, zData, nData, xDel, SQLITE_UTF8);
}
int sqlite3_bind_text16(
  sqlite3_stmt *pStmt, 
  int i, 
  const void *zData, 
  int nData, 
  void (*xDel)(void*)
){
  return bindText(pStmt, i, zData, nData, xDel, SQLITE_UTF16NATIVE);
}

/*
** Return the number of wildcards that can be potentially bound to.
** This routine is added to support DBD::SQLite.  
*/
int sqlite3_bind_parameter_count(sqlite3_stmt *pStmt){
  Vdbe *p = (Vdbe*)pStmt;
  return p ? p->nVar : 0;
}

/*
** Create a mapping from variable numbers to variable names
** in the Vdbe.azVar[] array, if such a mapping does not already
** exist.
*/
static void createVarMap(Vdbe *p){
  if( !p->okVar ){
    int j;
    Op *pOp;
    for(j=0, pOp=p->aOp; j<p->nOp; j++, pOp++){
      if( pOp->opcode==OP_Variable ){
        assert( pOp->p1>0 && pOp->p1<=p->nVar );
        p->azVar[pOp->p1-1] = pOp->p3;
      }
    }
    p->okVar = 1;
  }
}

/*
** Return the name of a wildcard parameter.  Return NULL if the index
** is out of range or if the wildcard is unnamed.
**
** The result is always UTF-8.
*/
const char *sqlite3_bind_parameter_name(sqlite3_stmt *pStmt, int i){
  Vdbe *p = (Vdbe*)pStmt;
  if( p==0 || i<1 || i>p->nVar ){
    return 0;
  }
  createVarMap(p);
  return p->azVar[i-1];
}

/*
** Given a wildcard parameter name, return the index of the variable
** with that name.  If there is no variable with the given name,
** return 0.
*/
int sqlite3_bind_parameter_index(sqlite3_stmt *pStmt, const char *zName){
  Vdbe *p = (Vdbe*)pStmt;
  int i;
  if( p==0 ){
    return 0;
  }
  createVarMap(p); 
  for(i=0; i<p->nVar; i++){
    const char *z = p->azVar[i];
    if( z && strcmp(z,zName)==0 ){
      return i+1;
    }
  }
  return 0;
}

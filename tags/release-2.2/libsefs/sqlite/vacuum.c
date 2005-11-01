/*
** 2003 April 6
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This file contains code used to implement the VACUUM command.
**
** Most of the code in this file may be omitted by defining the
** SQLITE_OMIT_VACUUM macro.
**
** $Id: vacuum.c,v 1.32 2004/09/17 20:02:42 drh Exp $
*/
#include "sqliteInt.h"
#include "os.h"

#if !defined(SQLITE_OMIT_VACUUM) || SQLITE_OMIT_VACUUM
/*
** Generate a random name of 20 character in length.
*/
static void randomName(unsigned char *zBuf){
  static const unsigned char zChars[] =
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789";
  int i;
  sqlite3Randomness(20, zBuf);
  for(i=0; i<20; i++){
    zBuf[i] = zChars[ zBuf[i]%(sizeof(zChars)-1) ];
  }
}

/*
** Execute zSql on database db. Return an error code.
*/
static int execSql(sqlite3 *db, const char *zSql){
  sqlite3_stmt *pStmt;
  if( SQLITE_OK!=sqlite3_prepare(db, zSql, -1, &pStmt, 0) ){
    return sqlite3_errcode(db);
  }
  while( SQLITE_ROW==sqlite3_step(pStmt) );
  return sqlite3_finalize(pStmt);
}

/*
** Execute zSql on database db. The statement returns exactly
** one column. Execute this as SQL on the same database.
*/
static int execExecSql(sqlite3 *db, const char *zSql){
  sqlite3_stmt *pStmt;
  int rc;

  rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
  if( rc!=SQLITE_OK ) return rc;

  while( SQLITE_ROW==sqlite3_step(pStmt) ){
    rc = execSql(db, sqlite3_column_text(pStmt, 0));
    if( rc!=SQLITE_OK ){
      sqlite3_finalize(pStmt);
      return rc;
    }
  }

  return sqlite3_finalize(pStmt);
}

#endif

/*
** The non-standard VACUUM command is used to clean up the database,
** collapse free space, etc.  It is modelled after the VACUUM command
** in PostgreSQL.
**
** In version 1.0.x of SQLite, the VACUUM command would call
** gdbm_reorganize() on all the database tables.  But beginning
** with 2.0.0, SQLite no longer uses GDBM so this command has
** become a no-op.
*/
void sqlite3Vacuum(Parse *pParse, Token *pTableName){
  Vdbe *v = sqlite3GetVdbe(pParse);
  if( v ){
    sqlite3VdbeAddOp(v, OP_Vacuum, 0, 0);
  }
  return;
}

/*
** This routine implements the OP_Vacuum opcode of the VDBE.
*/
int sqlite3RunVacuum(char **pzErrMsg, sqlite3 *db){
  int rc = SQLITE_OK;     /* Return code from service routines */
#if !defined(SQLITE_OMIT_VACUUM) || SQLITE_OMIT_VACUUM
  const char *zFilename;  /* full pathname of the database file */
  int nFilename;          /* number of characters  in zFilename[] */
  char *zTemp = 0;        /* a temporary file in same directory as zFilename */
  int i;                  /* Loop counter */
  Btree *pMain;           /* The database being vacuumed */
  Btree *pTemp;
  char *zSql = 0;

  if( !db->autoCommit ){
    sqlite3SetString(pzErrMsg, "cannot VACUUM from within a transaction", 
       (char*)0);
    rc = SQLITE_ERROR;
    goto end_of_vacuum;
  }

  /* Get the full pathname of the database file and create a
  ** temporary filename in the same directory as the original file.
  */
  pMain = db->aDb[0].pBt;
  zFilename = sqlite3BtreeGetFilename(pMain);
  assert( zFilename );
  if( zFilename[0]=='\0' ){
    /* The in-memory database. Do nothing. Return directly to avoid causing
    ** an error trying to DETACH the vacuum_db (which never got attached)
    ** in the exit-handler.
    */
    return SQLITE_OK;
  }
  nFilename = strlen(zFilename);
  zTemp = sqliteMalloc( nFilename+100 );
  if( zTemp==0 ){
    rc = SQLITE_NOMEM;
    goto end_of_vacuum;
  }
  strcpy(zTemp, zFilename);
  i = 0;
  do {
    zTemp[nFilename] = '-';
    randomName((unsigned char*)&zTemp[nFilename+1]);
  } while( i<10 && sqlite3OsFileExists(zTemp) );

  /* Attach the temporary database as 'vacuum_db'. The synchronous pragma
  ** can be set to 'off' for this file, as it is not recovered if a crash
  ** occurs anyway. The integrity of the database is maintained by a
  ** (possibly synchronous) transaction opened on the main database before
  ** sqlite3BtreeCopyFile() is called.
  **
  ** An optimisation would be to use a non-journaled pager.
  */
  zSql = sqlite3MPrintf("ATTACH '%q' AS vacuum_db;", zTemp);
  if( !zSql ){
    rc = SQLITE_NOMEM;
    goto end_of_vacuum;
  }
  rc = execSql(db, zSql);
  sqliteFree(zSql);
  zSql = 0;
  if( rc!=SQLITE_OK ) goto end_of_vacuum;
  assert( strcmp(db->aDb[db->nDb-1].zName,"vacuum_db")==0 );
  pTemp = db->aDb[db->nDb-1].pBt;
  sqlite3BtreeSetPageSize(pTemp, sqlite3BtreeGetPageSize(pMain),
     sqlite3BtreeGetReserve(pMain));
  assert( sqlite3BtreeGetPageSize(pTemp)==sqlite3BtreeGetPageSize(pMain) );
  execSql(db, "PRAGMA vacuum_db.synchronous=OFF");

  /* Begin a transaction */
  rc = execSql(db, "BEGIN;");
  if( rc!=SQLITE_OK ) goto end_of_vacuum;

  /* Query the schema of the main database. Create a mirror schema
  ** in the temporary database.
  */
  rc = execExecSql(db, 
      "SELECT 'CREATE TABLE vacuum_db.' || substr(sql,14,100000000) "
      "  FROM sqlite_master WHERE type='table' "
      "UNION ALL "
      "SELECT 'CREATE INDEX vacuum_db.' || substr(sql,14,100000000) "
      "  FROM sqlite_master WHERE sql LIKE 'CREATE INDEX %' "
      "UNION ALL "
      "SELECT 'CREATE UNIQUE INDEX vacuum_db.' || substr(sql,21,100000000) "
      "  FROM sqlite_master WHERE sql LIKE 'CREATE UNIQUE INDEX %'"
      "UNION ALL "
      "SELECT 'CREATE VIEW vacuum_db.' || substr(sql,13,100000000) "
      "  FROM sqlite_master WHERE type='view'"
  );
  if( rc!=SQLITE_OK ) goto end_of_vacuum;

  /* Loop through the tables in the main database. For each, do
  ** an "INSERT INTO vacuum_db.xxx SELECT * FROM xxx;" to copy
  ** the contents to the temporary database.
  */
  rc = execExecSql(db, 
      "SELECT 'INSERT INTO vacuum_db.' || quote(name) "
      "|| ' SELECT * FROM ' || quote(name) || ';'"
      "FROM sqlite_master "
      "WHERE type = 'table';"
  );
  if( rc!=SQLITE_OK ) goto end_of_vacuum;

  /* Copy the triggers from the main database to the temporary database.
  ** This was deferred before in case the triggers interfered with copying
  ** the data. It's possible the indices should be deferred until this
  ** point also.
  */
  rc = execExecSql(db, 
      "SELECT 'CREATE TRIGGER  vacuum_db.' || substr(sql, 16, 1000000) "
      "FROM sqlite_master WHERE type='trigger'"
  );
  if( rc!=SQLITE_OK ) goto end_of_vacuum;


  /* At this point, unless the main db was completely empty, there is now a
  ** transaction open on the vacuum database, but not on the main database.
  ** Open a btree level transaction on the main database. This allows a
  ** call to sqlite3BtreeCopyFile(). The main database btree level
  ** transaction is then committed, so the SQL level never knows it was
  ** opened for writing. This way, the SQL transaction used to create the
  ** temporary database never needs to be committed.
  */
  if( sqlite3BtreeIsInTrans(pTemp) ){
    u32 meta;

    assert( 0==sqlite3BtreeIsInTrans(pMain) );
    rc = sqlite3BtreeBeginTrans(pMain, 1);
    if( rc!=SQLITE_OK ) goto end_of_vacuum;

    /* Copy Btree meta values 3 and 4. These correspond to SQL layer meta 
    ** values 2 and 3, the default values of a couple of pragmas.
    */
    rc = sqlite3BtreeGetMeta(pMain, 3, &meta);
    if( rc!=SQLITE_OK ) goto end_of_vacuum;
    rc = sqlite3BtreeUpdateMeta(pTemp, 3, meta);
    if( rc!=SQLITE_OK ) goto end_of_vacuum;
    rc = sqlite3BtreeGetMeta(pMain, 4, &meta);
    if( rc!=SQLITE_OK ) goto end_of_vacuum;
    rc = sqlite3BtreeUpdateMeta(pTemp, 4, meta);
    if( rc!=SQLITE_OK ) goto end_of_vacuum;

    rc = sqlite3BtreeCopyFile(pMain, pTemp);
    if( rc!=SQLITE_OK ) goto end_of_vacuum;
    rc = sqlite3BtreeCommit(pMain);
  }

end_of_vacuum:
  /* Currently there is an SQL level transaction open on the vacuum
  ** database. No locks are held on any other files (since the main file
  ** was committed at the btree level). So it safe to end the transaction
  ** by manually setting the autoCommit flag to true and detaching the
  ** vacuum database. The vacuum_db journal file is deleted when the pager
  ** is closed by the DETACH.
  */
  db->autoCommit = 1;
  if( rc==SQLITE_OK ){
    rc = execSql(db, "DETACH vacuum_db;");
  }else{
    execSql(db, "DETACH vacuum_db;");
  }
  if( zTemp ){
    sqlite3OsDelete(zTemp);
    sqliteFree(zTemp);
  }
  if( zSql ) sqliteFree( zSql );
  sqlite3ResetInternalSchema(db, 0);
#endif
  return rc;
}

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include <math.h>

#include "worker.h"
#include "gps.h"
#include "parsers.h"

int do_nothing(void *not_used, int argc, char **argv, char **col_name)
{
  return 0;
}

int init_beacon_db(const char *db_file, sqlite3 **db)
{
  int ret;
  if ((ret = sqlite3_open(db_file, db)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(*db));
    sqlite3_close(*db);
    return ret;
  }

  char *sql;
  sql = "create table if not exists authmode("
    "id integer not null primary key,"
    "mode text"
    ");";
  if((ret = sqlite3_exec(*db, sql, do_nothing, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(*db));
    sqlite3_close(*db);
    return ret;
  }
  sql = "create table if not exists ap("
    "id integer not null primary key,"
    "bssid text not null,"
    "ssid text not null,"
    "unique (bssid, ssid)"
    ");";
  if((ret = sqlite3_exec(*db, sql, do_nothing, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(*db));
    sqlite3_close(*db);
    return ret;
  }
  sql = "create table if not exists beacon("
    "ts integer,"
    "ap integer,"
    "rssi integer,"
    "lat float,"
    "lon float,"
    "alt float,"
    "authmode integer,"
    "foreign key(ap) references ap(id),"
    "foreign key(authmode) references authmode(id)"
    ");";
  if((ret = sqlite3_exec(*db, sql, do_nothing, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(*db));
    sqlite3_close(*db);
    return ret;
  }
  return 0;
}

int search_authmode(const char *authmode, sqlite3 *db)
{
  char *sql;
  sqlite3_stmt *stmt;
  int authmode_id = 0, ret;

  // look for an existing ap_info in the db
  sql = "select id from authmode where mode=?;";
  if ((ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
    return ret * -1;
  } else {
    if ((ret = sqlite3_bind_text(stmt, 1, authmode, -1, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
      return ret * -1;
    }

    while ((ret = sqlite3_step(stmt)) != SQLITE_DONE) {
      if (ret == SQLITE_ERROR) {
        fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
        break;
      } else if (ret == SQLITE_ROW) {
        authmode_id = sqlite3_column_int(stmt, 0);
      } else {
        fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
        break;
      }
    }
    sqlite3_finalize(stmt);
  }
  return authmode_id;
}

int insert_authmode(const char *authmode, sqlite3 *db)
{
    // insert the authmode into the db
  int ret, authmode_id = 0;
  char sql[128];

  authmode_id = search_authmode(authmode, db);
  if (!authmode_id) {
    snprintf(sql, 128, "insert into authmode (mode) values (\"%s\");", authmode);
    if((ret = sqlite3_exec(db, sql, do_nothing, 0, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return ret * -1;
    }
    authmode_id = search_authmode(authmode, db);
  }

  return authmode_id;
}

int search_ap(struct ap_info ap, sqlite3 *db)
{
  char *sql;
  sqlite3_stmt *stmt;
  int ap_id = 0, ret;

  // look for an existing ap_info in the db
  sql = "select id from ap where bssid=? and ssid=?;";
  if ((ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
    return ret * -1;
  } else {
    if ((ret = sqlite3_bind_text(stmt, 1, ap.bssid, -1, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
      return ret * -1;
    }
    if ((ret = sqlite3_bind_text(stmt, 2, ap.ssid, -1, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
      return ret * -1;
    }

    while ((ret = sqlite3_step(stmt)) != SQLITE_DONE) {
      if (ret == SQLITE_ERROR) {
        fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
        break;
      } else if (ret == SQLITE_ROW) {
        ap_id = sqlite3_column_int(stmt, 0);
      } else {
        fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
        break;
      }
    }
    sqlite3_finalize(stmt);
  }
  return ap_id;
}

int insert_ap(struct ap_info ap, sqlite3 *db)
{
    // insert the ap_info into the db
  int ret, ap_id = 0;
  char sql[128];

  ap_id = search_ap(ap, db);
  if (!ap_id) {
    // if ever the ssid is longer than 32 chars, it is truncated at 128-18-length of string below
    snprintf(sql, 128, "insert into ap (bssid, ssid) values (\"%s\", \"%s\");", ap.bssid, ap.ssid);
    if((ret = sqlite3_exec(db, sql, do_nothing, 0, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return ret * -1;
    }
    ap_id = search_ap(ap, db);
  }

  return ap_id;
}

int insert_beacon(struct ap_info ap, struct gps_loc gloc, sqlite3 *db)
{
  int ap_id, authmode_id, ret;

  ap_id = insert_ap(ap, db);
  char *authmode = authmode_from_crypto(ap.rsn, ap.msw, ap.ess, ap.privacy, ap.wps);
  authmode_id = insert_authmode(authmode, db);
  time_t now = time(NULL);

  char sql[256];
  snprintf(sql, 256, "insert into beacon (ts, ap, rssi, lat, lon, alt, authmode)"
    "values (%lu, %u, %d, %f, %f, %f, %d);",
    now, ap_id, ap.rssi, gloc.lat, gloc.lon, isnan(gloc.alt) ? 0.0 : gloc.alt, authmode_id);
  if((ret = sqlite3_exec(db, sql, do_nothing, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return ret * -1;
  }

  return 0;
}

int begin_txn(sqlite3 *db)
{
  int ret;
  char sql[32];

  snprintf(sql, 32, "begin transaction;");
  if((ret = sqlite3_exec(db, sql, do_nothing, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return ret * -1;
  }

  return 0;
}

int commit_txn(sqlite3 *db)
{
  int ret;
  char sql[32];

  snprintf(sql, 32, "commit transaction;");
  if((ret = sqlite3_exec(db, sql, do_nothing, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return ret * -1;
  }

  return 0;
}

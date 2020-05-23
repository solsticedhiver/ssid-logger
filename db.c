/*
ssid-logger is a simple software to log SSID you encounter in your vicinity
Copyright © 2020 solsTiCe d'Hiver
*/
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>
#include <libgen.h>

#include "ap_info.h"
#include "gps_thread.h"
#include "parsers.h"
#include "lruc.h"

int init_beacon_db(const char *db_file, sqlite3 **db)
{
  int ret;
  if ((ret = sqlite3_open(db_file, db)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(*db), basename(__FILE__), __LINE__, __func__);
    sqlite3_close(*db);
    return ret;
  }

  char *sql;
  sql = "create table if not exists authmode("
    "id integer not null primary key,"
    "mode text"
    ");";
  if ((ret = sqlite3_exec(*db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(*db), basename(__FILE__), __LINE__, __func__);
    sqlite3_close(*db);
    return ret;
  }
  sql = "create table if not exists ap("
    "id integer not null primary key,"
    "bssid text not null,"
    "ssid text not null,"
    "unique (bssid, ssid)"
    ");";
  if ((ret = sqlite3_exec(*db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(*db), basename(__FILE__), __LINE__, __func__);
    sqlite3_close(*db);
    return ret;
  }
  sql = "create table if not exists beacon("
    "ts integer,"
    "ap integer,"
    "channel integer,"
    "rssi integer,"
    "lat float,"
    "lon float,"
    "alt float,"
    "acc float,"
    "authmode integer,"
    "foreign key(ap) references ap(id),"
    "foreign key(authmode) references authmode(id)"
    ");";
  if ((ret = sqlite3_exec(*db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(*db), basename(__FILE__), __LINE__, __func__);
    sqlite3_close(*db);
    return ret;
  }
  sql = "pragma synchronous = normal;";
  if ((ret = sqlite3_exec(*db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(*db), basename(__FILE__), __LINE__, __func__);
    return ret;
  }
  sql = "pragma temp_store = 2;"; // to store temp table and indices in memory
  if ((ret = sqlite3_exec(*db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(*db), basename(__FILE__), __LINE__, __func__);
    sqlite3_close(*db);
    return ret;
  }
  sql = "pragma journal_mode = off;"; // disable journal for rollback (we don't use this)
  if ((ret = sqlite3_exec(*db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(*db), basename(__FILE__), __LINE__, __func__);
    sqlite3_close(*db);
    return ret;
  }
  sql = "pragma foreign_keys = on;"; // this needs to be turn on
  if ((ret = sqlite3_exec(*db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(*db), basename(__FILE__), __LINE__, __func__);
    sqlite3_close(*db);
    return ret;
  }

  return 0;
}

int64_t search_authmode(const char *authmode, sqlite3 *db)
{
  char *sql;
  sqlite3_stmt *stmt;
  int64_t authmode_id = 0, ret;

  // look for an existing ap_info in the db
  sql = "select id from authmode where mode=?;";
  if ((ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
    return ret * -1;
  } else {
    if ((ret = sqlite3_bind_text(stmt, 1, authmode, -1, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
      return ret * -1;
    }

    while ((ret = sqlite3_step(stmt)) != SQLITE_DONE) {
      if (ret == SQLITE_ERROR) {
        fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
        break;
      } else if (ret == SQLITE_ROW) {
        authmode_id = sqlite3_column_int64(stmt, 0);
      } else {
        fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
        break;
      }
    }
    sqlite3_finalize(stmt);
  }
  return authmode_id;
}

int64_t insert_authmode(const char *authmode, sqlite3 *db)
{
    // insert the authmode into the db
  int64_t ret, authmode_id = 0;
  char sql[65 + MAX_AUTHMODE_LEN];

  authmode_id = search_authmode(authmode, db);
  if (!authmode_id) {
    snprintf(sql, 128, "insert into authmode (mode) values (\"%s\");", authmode);
    if ((ret = sqlite3_exec(db, sql, NULL, 0, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
      return ret * -1;
    }
    authmode_id = search_authmode(authmode, db);
  }

  return authmode_id;
}

int64_t search_ap(struct ap_info ap, sqlite3 *db)
{
  char *sql;
  sqlite3_stmt *stmt;
  int64_t ap_id = 0, ret;

  // look for an existing ap_info in the db
  sql = "select id from ap where bssid=? and ssid=?;";
  if ((ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
    return ret * -1;
  } else {
    if ((ret = sqlite3_bind_text(stmt, 1, ap.bssid, -1, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
      return ret * -1;
    }
    if ((ret = sqlite3_bind_text(stmt, 2, ap.ssid, -1, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
      return ret * -1;
    }

    while ((ret = sqlite3_step(stmt)) != SQLITE_DONE) {
      if (ret == SQLITE_ERROR) {
        fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
        break;
      } else if (ret == SQLITE_ROW) {
        ap_id = sqlite3_column_int64(stmt, 0);
      } else {
        fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
        break;
      }
    }
    sqlite3_finalize(stmt);
  }
  return ap_id;
}

int64_t insert_ap(struct ap_info ap, sqlite3 *db)
{
    // insert the ap_info into the db
  int64_t ret, ap_id = 0;
  char sql[128];

  ap_id = search_ap(ap, db);
  if (!ap_id) {
    // if ever the ssid is longer than 32 chars, it is truncated at 128-18-length of string below
    snprintf(sql, 128, "insert into ap (bssid, ssid) values (\"%s\", \"%s\");", ap.bssid, ap.ssid);
    if ((ret = sqlite3_exec(db, sql, NULL, 0, NULL)) != SQLITE_OK) {
      fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
      return ret * -1;
    }
    ap_id = search_ap(ap, db);
  }

  return ap_id;
}

int insert_beacon(struct ap_info ap, struct gps_loc gloc, sqlite3 *db, lruc *authmode_pk_cache, lruc *ap_pk_cache)
{
  int ret;
  int64_t ap_id = 0, authmode_id = 0;
  void *value = NULL;

  // look for ap in ap_pk_cache
  size_t ap_key_len = 18 + ap.ssid_len;
  char *ap_key = malloc(ap_key_len * sizeof(char));
  // concat bssid and ssid to use it as key in ap_pk_cache
  snprintf(ap_key, ap_key_len + 1, "%s%s", ap.bssid, ap.ssid);
  lruc_get(ap_pk_cache, ap_key, ap_key_len, &value);
  if (value == NULL) {
    ap_id = insert_ap(ap, db);
    // insert ap_id in ap_pk_cache
    int64_t *new_value = malloc(sizeof(int64_t));
    *new_value = ap_id;
    lruc_set(ap_pk_cache, ap_key, ap_key_len, new_value, 1);
  } else {
    ap_id = *(int64_t *)value;
    free(ap_key);
  }

  value = NULL;
  // look for authmode in authmode_pk_cache
  char *authmode = authmode_from_crypto(ap.rsn, ap.msw, ap.ess, ap.privacy, ap.wps);
  lruc_get(authmode_pk_cache, authmode, strlen(authmode), &value);
  if (value == NULL) {
    authmode_id = insert_authmode(authmode, db);
    if (authmode_id < 0) {
      // something is wrong ! probably authmode is too long
      free(authmode);
      return authmode_id;
    }
    // insert authmode_id in authmode_pk_cache
    int64_t *new_value = malloc(sizeof(int64_t));
    *new_value = authmode_id;
    lruc_set(authmode_pk_cache, authmode, strlen(authmode), new_value, 1);
  } else {
    authmode_id = *(int64_t *)value;
    free(authmode);
  }

  char sql[256];
  snprintf(sql, 256, "insert into beacon (ts, ap, channel, rssi, lat, lon, alt, acc, authmode)"
    "values (%lu, %"PRId64", %u, %d, %f, %f, %f, %f, %"PRId64");",
    gloc.ftime.tv_sec, ap_id, ap.channel, ap.rssi, gloc.lat, gloc.lon, isnan(gloc.alt) ? 0.0 : gloc.alt, gloc.acc, authmode_id);
  if ((ret = sqlite3_exec(db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
    return ret * -1;
  }

  return 0;
}

int begin_txn(sqlite3 *db)
{
  int ret;
  char sql[32];

  snprintf(sql, 32, "begin transaction;");
  if ((ret = sqlite3_exec(db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
    return ret * -1;
  }

  return 0;
}

int commit_txn(sqlite3 *db)
{
  int ret;
  char sql[32];

  snprintf(sql, 32, "commit transaction;");
  if ((ret = sqlite3_exec(db, sql, NULL, 0, NULL)) != SQLITE_OK) {
    fprintf(stderr, "Error: %s (%s:%d in %s)\n", sqlite3_errmsg(db), basename(__FILE__), __LINE__, __func__);
    return ret * -1;
  }

  return 0;
}

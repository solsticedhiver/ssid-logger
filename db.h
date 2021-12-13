#ifndef DB_H
#define DB_H

#include <sqlite3.h>
#include "lruc.h"

// to avoid SD-card wear, we avoid writing to disk every seconds, setting a delay between each transactions
#define DB_CACHE_TIME 60    // time in second between transaction

int init_beacon_db(const char *db_file, sqlite3 **db);
int search_ap(struct libwifi_bss bss, sqlite3 *db);
int insert_ap(struct libwifi_bss bss, sqlite3 *db);
int search_authmode(const char *authmode, sqlite3 *db);
int insert_authmode(const char *authmode, sqlite3 *db);
int insert_beacon(struct libwifi_bss bss, struct gps_loc gloc, sqlite3 *db, lruc *authmode_pk_cache, lruc *ap_pk_cache);
int begin_txn(sqlite3 *db);
int commit_txn(sqlite3 *db);

#endif

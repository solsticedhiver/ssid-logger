#ifndef DB_H
#define DB_H

#include <sqlite3.h>

// to avoid SD-card wear, we avoid writing to disk every seconds, setting a delay between each transactions
#define DB_CACHE_TIME 60    // time in second between transaction

int init_beacon_db(const char *db_file, sqlite3 **db);
int search_ap(struct ap_info ap, sqlite3 *db);
int insert_ap(struct ap_info ap, sqlite3 *db);
int search_authmode(const char *authmode, sqlite3 *db);
int insert_authmode(const char *authmode, sqlite3 *db);
int insert_beacon(struct ap_info ap, struct gps_loc gloc, sqlite3 *db);
int begin_txn(sqlite3 *db);
int commit_txn(sqlite3 *db);

#endif

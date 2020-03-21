#ifndef DB_H
#define DB_H

#include <sqlite3.h>

int init_beacon_db(const char *db_file, sqlite3 **db);
int search_ap(struct ap_info ap, sqlite3 *db);
int insert_ap(struct ap_info ap, sqlite3 *db);
int search_authmode(const char *authmode, sqlite3 *db);
int insert_authmode(const char *authmode, sqlite3 *db);
int insert_beacon(struct ap_info ap, struct gps_loc gloc, sqlite3 *db);

#endif

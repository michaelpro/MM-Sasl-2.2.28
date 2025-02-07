#ifndef MYSQL_PLUGIN_H
#define MYSQL_PLUGIN_H

// struct defiition for sql_settings


typedef struct sql_settings {
    char *sql_user;
    char *sql_passwd;
    char *sql_hostnames;
    char *sql_database;
    char *sql_select;
    char *sql_insert;
    char *sql_update;
    int sql_port;
    int sql_usessl;
} sql_settings_t;

int mariadb_init(sql_settings_t *settings);
char * sql_auth(const char *login, const char *password, const char *service, const char *realm);
void mariadb_deinit(void);
int initialize_mysql_config(void);
#endif // MYSQL_PLUGIN_H
#include <stdio.h>
#include <stdlib.h>
#include <mysql.h>
#include <string.h>
#include <argon2.h> // MUST have installed libargon2 and included its header
#include <syslog.h>
#include <unistd.h> // For F_OK
#include "sasl.h"
#include "saslplug.h"
#include "mysql_plugin.h"
#include "mechanisms.h"
#include "globals.h" /* mech_option */
#include "plugin_common.h"
#include "cfile.h"

// Global static variables for prepared statement caching
static cfile cf = 0;
static MYSQL *db_conn = NULL;
static MYSQL_STMT *stmt = NULL;
static const char *query = "SELECT password FROM mailbox WHERE username=? LIMIT 1";
static sql_settings_t *config = NULL;
#define BIG_ENOUGH 4096

int initialize_mysql_config(void)
{
    int ret = 0;
    if (config == NULL)
    {
        config = malloc(sizeof(struct sql_settings));
        if (config == NULL)
        {
            syslog(LOG_ERR, "Could not allocate memory for config settings sql_settings");
        }
    }

    char complaint[BIG_ENOUGH];

    char *configname = NULL;
    /* name of config file may be given with -O option */
    if (mech_option)
    {
        configname = mech_option;
    }
    else if (access("/usr/local/etc/saslauthd.conf", F_OK) == 0)
    {
        configname = "/usr/local/etc/saslauthd.conf";
    }
    else
    {
        configname = NULL;
    }

    if (configname)
    {
        if (!(cf = cfile_read(configname, complaint, sizeof(complaint))))
        {
            syslog(LOG_ERR, "mysql_plugin_new error line 58 reading config file %s", complaint);
            return -1;
        }
    }
    if (cf)
    {
        // Initialize config structure with values from config file
        const char *host = cfile_getstring(cf, "sql_hostname", "localhost");
        size_t host_len = strlen(host);
        config->sql_hostnames = malloc(host_len + 1);
        if (config->sql_hostnames)
            strcpy(config->sql_hostnames, host);

        const char *user = cfile_getstring(cf, "sql_user", "root");
        size_t user_len = strlen(user);
        config->sql_user = malloc(user_len + 1);
        if (config->sql_user)
            strcpy(config->sql_user, user);

        const char *password = cfile_getstring(cf, "sql_passwd", "");
        size_t password_len = strlen(password);
        config->sql_passwd = malloc(password_len + 1);
        if (config->sql_passwd)
            strcpy(config->sql_passwd, password);

        const char *database = cfile_getstring(cf, "sql_database", "postfixadmin");
        size_t database_len = strlen(database);
        config->sql_database = malloc(database_len + 1);
        if (config->sql_database)
            strcpy(config->sql_database, database);

        config->sql_port = cfile_getint(cf, "sql_port", 3306);
        config->sql_usessl = cfile_getswitch(cf, "sql_ssl", 0);

        const char *select = cfile_getstring(cf, "sql_select", "SELECT password FROM mailbox WHERE username=? LIMIT 1");
        size_t select_len = strlen(select);
        config->sql_select = malloc(select_len + 1);
        if (config->sql_select)
            strcpy(config->sql_select, select);
    }
    else
    {
        syslog(LOG_ERR, "Could not read config file");
        return -1;
    }
    // Free the cfile structure once you've read all necessary data
    cfile_free(cf);
    return ret;
}

// Initialize the connection and prepare the statement
int mariadb_init(sql_settings_t *settings)
{
    initialize_mysql_config();
    db_conn = mysql_init(NULL);
    if (!mysql_real_connect(db_conn, settings->sql_hostnames, settings->sql_user, settings->sql_passwd, settings->sql_database, 0, NULL, 0))
    {
        syslog(LOG_ERR, "Error connecting to MySQL: %s", mysql_error(db_conn));
        return -1; // Error
    }

    stmt = mysql_stmt_init(db_conn);

    if (!stmt)
    {
        syslog(LOG_ERR, "mysql_stmt_init(), out of memory");
        return -1;
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query)))
    {
        syslog(LOG_ERR, "mysql_stmt_prepare(), SELECT failed");
        mysql_stmt_close(stmt);
        stmt = NULL;
        return -1;
    }

    return 0; // Success
}

// Authentication function
char *sql_auth(const char *login, const char *password, const char *service, const char *realm)
{
    // int ret = SASL_FAIL;
    //  Passwords in the database include metadata like the hash type and salt
    //  We need to extract the hash and verify the password using argon2 function appropriate for the hash type
    //  {ARGON2I}$argon2i$v=19$m=65536,t=4,p=1$UEF... is an example format
    //  Extract the hash type and the hash from the database result

    char *ret = NULL;
    MYSQL_BIND bind_param = {0}, bind_result = {0};
    char hash_from_db[512] = {0}; // Assuming the hash fits in 512 chars

    if (db_conn == NULL)
    {
        if (mariadb_init(config) == -1)
        {
            return strdup("Database initialization failed");
        }
    }
    if (stmt == NULL)
    {
        stmt = mysql_stmt_init(db_conn);
        if (mysql_stmt_prepare(stmt, query, strlen(query)))
        {
            syslog(LOG_ERR, "mysql_stmt_prepare(), SELECT failed");
            mysql_stmt_close(stmt);
            stmt = NULL;
            return strdup("mysql_stmt_prepare(), SELECT failed");
        }
    }
    if (db_conn == NULL || stmt == NULL)
    {
        if (mariadb_init(config) != 0)
        {
            return strdup("Database initialization failed");
        }
    }
    // break here.
    // Bind the parameter for the prepared statement
    bind_param.buffer_type = MYSQL_TYPE_STRING;
    bind_param.buffer = (void *)login;
    bind_param.buffer_length = strlen(login);

    if (mysql_stmt_bind_param(stmt, &bind_param))
    {
        syslog(LOG_ERR, "mysql_stmt_bind_param() failed");
        return strdup("mysql_stmt_bind_param() failed");
    }

    // Bind the result. We're expecting a string (the hash)
    bind_result.buffer_type = MYSQL_TYPE_STRING;
    bind_result.buffer = hash_from_db;
    bind_result.buffer_length = sizeof(hash_from_db) - 1; // Leave room for null terminator
    bind_result.length = 0;

    if (mysql_stmt_bind_result(stmt, &bind_result))
    {
        syslog(LOG_ERR, "mysql_stmt_bind_result() failed");
        return strdup("mysql_stmt_bind_result() failed");
    }

    if (mysql_stmt_execute(stmt))
    {
        syslog(LOG_ERR, "mysql_stmt_execute(), failed");
        return strdup("mysql_stmt_execute(), failed");
    }

    if (mysql_stmt_store_result(stmt) || mysql_stmt_fetch(stmt) != 0)
    {
        // No user or fetch error
        goto cleanup;
    }
    char *hash_type = strtok(hash_from_db, "$");
    char *hash_data = strtok(NULL, "}");

    if (hash_type == NULL || hash_data == NULL)
    {
        syslog(LOG_ERR, "Invalid hash format in database");
        return strdup("Invalid hash format in database");
    }
    char *full_hash = malloc(strlen(hash_data) + 3);
    if (full_hash == NULL)
    {
        syslog(LOG_ERR, "Memory allocation failed");
        return strdup("Memory allocation failed");
    } else {
        strcpy(full_hash, "$");
        strcat(full_hash, hash_data);
    }

    // hash_type now contains "{ARGON2I}" or "{ARGON2ID}"
    // hash_data now contains "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$someencodedhash"

    // Strip the '{' from hash_type to get the actual hash type
    if (hash_type[0] == '{')
        hash_type++;

    // Now verify based on the extracted hash type
    if (strncmp(hash_type, "ARGON2ID", 8) == 0)
    {
        if (argon2_verify(full_hash, password, strlen(password), Argon2_id) == ARGON2_OK)
        {
            free(ret);
            free(full_hash);
            ret = strdup("OK");
        }
        else
        {
            free(ret);
            free(full_hash);
            ret = strdup("NO");
            syslog(LOG_DEBUG, "Password verification failed");
        }
    }
    else if (strncmp(hash_type, "ARGON2I", 7) == 0)
    {
        int Result = argon2_verify(full_hash, password, strlen(password), Argon2_i);
        if (Result == ARGON2_OK)
        {
            free(ret);
            free(full_hash);
            ret = strdup("OK");
        }
        else
        {
            syslog(LOG_DEBUG, "Password verification failed %d", Result);
            free(full_hash);
            free(ret);
            ret = strdup("NO");
            
        }
    }
    else
    {
        syslog(LOG_ERR, "Unsupported hash type: %s", hash_type);
        free(ret);
        free(full_hash);
        ret = strdup("Unsupported hash type");
    }

cleanup:
    mysql_stmt_free_result(stmt);
    return ret;
}

// Cleanup function (to be called when shutting down)

static void sql_cleanup(void)
{
    if (stmt)
    {
        mysql_stmt_close(stmt);
        stmt = NULL;
    }
    if (db_conn)
    {
        mysql_close(db_conn);
        db_conn = NULL;
    }
}

void mariadb_deinit(void)
{
    sql_cleanup();
    if (config)
    {
        free(config->sql_hostnames);
        free(config->sql_user);
        free(config->sql_passwd);
        free(config->sql_database);
        free(config);
        config = NULL;
    }
}

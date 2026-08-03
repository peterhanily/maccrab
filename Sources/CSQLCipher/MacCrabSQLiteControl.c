#include "MacCrabSQLiteControl.h"

int maccrab_sqlite_take_checkpoint_ownership(sqlite3 *db) {
    int no_checkpoint_on_close = 0;
    int rc;

    if (db == 0) {
        return SQLITE_MISUSE;
    }

    /* Passing zero removes SQLite's default auto-checkpoint WAL hook. */
    rc = sqlite3_wal_autocheckpoint(db, 0);
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = sqlite3_db_config(
        db,
        SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        1,
        &no_checkpoint_on_close
    );
    if (rc != SQLITE_OK) {
        return rc;
    }
    return no_checkpoint_on_close == 1 ? SQLITE_OK : SQLITE_ERROR;
}

int maccrab_sqlite_no_checkpoint_on_close(sqlite3 *db, int *is_disabled) {
    if (db == 0 || is_disabled == 0) {
        return SQLITE_MISUSE;
    }
    return sqlite3_db_config(
        db,
        SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        -1,
        is_disabled
    );
}

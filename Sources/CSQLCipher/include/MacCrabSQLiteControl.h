#ifndef MACCRAB_SQLITE_CONTROL_H
#define MACCRAB_SQLITE_CONTROL_H

#include "sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Claim checkpoint ownership for a MacCrab-managed connection.
 *
 * sqlite3_db_config() is variadic and therefore unavailable to Swift. This
 * narrow wrapper is the only project-owned bridge to
 * SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE. It also removes SQLite's default WAL hook;
 * Swift installs the floor-aware replacement immediately after this returns.
 */
int maccrab_sqlite_take_checkpoint_ownership(sqlite3 *db);

/* Read back the close-checkpoint setting without exposing a variadic call. */
int maccrab_sqlite_no_checkpoint_on_close(sqlite3 *db, int *is_disabled);

#ifdef __cplusplus
}
#endif

#endif /* MACCRAB_SQLITE_CONTROL_H */

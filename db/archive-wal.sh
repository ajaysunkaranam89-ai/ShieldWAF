#!/bin/sh
# archive_command for point-in-time recovery: copy one finished WAL segment to the archive folder, safely.
#   archive-wal.sh %p %f      (PostgreSQL substitutes the path and the file name)
# * never overwrites: a file that already exists must be identical (then it is a retry and counts as done), otherwise the command fails and PostgreSQL keeps the segment
#   and retries, so a name clash can never silently replace history;
# * written under a temporary name and renamed, so a half-written file is never taken for a segment;
# * fsync'ed before the rename, because PostgreSQL deletes its own copy as soon as this command succeeds.
# The archive folder (SHIELD_DB_ARCHIVE_DIR) must be a separate volume that is protected like the database: WAL files contain all data, in clear text.
set -eu
D="${SHIELD_DB_ARCHIVE_DIR:?SHIELD_DB_ARCHIVE_DIR is not set}"
SRC="$1"; NAME="$2"
case "$NAME" in *[!A-Za-z0-9._]*|"") echo "unexpected WAL file name" >&2; exit 1 ;; esac
if [ -f "$D/$NAME" ]; then
  cmp -s "$SRC" "$D/$NAME" && exit 0
  echo "$NAME already exists in the archive with different content" >&2; exit 1
fi
umask 077
cp "$SRC" "$D/$NAME.part"
sync "$D/$NAME.part" 2>/dev/null || sync
mv "$D/$NAME.part" "$D/$NAME"

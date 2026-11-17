# History and Reports

Scan history is stored locally in SQLite under the user configuration directory and pruned to the newest 2,000 records. The History tab shows recent entries and compares the latest two port snapshots for a normalized target, reporting new and removed ports.

The application provides native JSON export and port CSV export. Review exported files for credentials, URL query values, private hostnames, banners, and other sensitive information before distribution.

History is not encrypted and is not uploaded by the application. On supported Unix-style filesystems, the database is restricted to the current user. Delete the database while the application is closed to clear all local history. There is no general network comparison beyond the latest-two port snapshot diff.

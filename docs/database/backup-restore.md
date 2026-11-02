# Backup and restore

Design: [D9](../plan/steps/01-database.md#d9-retention-backup-and-restore-documentation-deliverables). MySQL holds metadata and configuration. Mail content is in S3, so a restore has to keep both consistent (see [Consistency with S3](#consistency-with-s3)).

> **RPO and RTO below are targets, not verified values.** They are verified by a restore drill in step 10.2.

| Target | Value (unverified)                                                     |
| ------ | ---------------------------------------------------------------------- |
| RPO    | ≤ 5 minutes (point-in-time recovery from continuously shipped binlogs) |
| RTO    | ≤ 1 hour for the primary database (restore to a new instance, repoint) |

## Local (Docker Compose)

Take the dump from the **replica**, so the primary is not loaded. Pass the root password through `MYSQL_PWD`, never on the command line:

```bash
docker compose exec -T mysql-replica sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -uroot --single-transaction --routines --triggers \
     --set-gtid-purged=OFF --databases email_gateway' > backup-$(date -u +%Y%m%dT%H%M%SZ).sql
```

`--single-transaction` gives a consistent InnoDB snapshot without locking. `--set-gtid-purged=OFF` makes the dump restorable into a fresh primary. The partition definitions are part of each `CREATE TABLE`, so they are restored as they were. MySQL Shell's `util.dumpSchemas(["email_gateway"], "<dir>", {threads: 4})` is a faster alternative for large local data sets.

Restore into a fresh volume, then rebuild the replica:

```bash
docker compose stop mysql mysql-replica
docker volume rm email-gateway_mysql-data email-gateway_mysql-replica-data   # destroys local data
docker compose up -d --wait mysql
docker compose exec -T mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot' < backup-<timestamp>.sql
docker compose up -d mysql-replica mysql-replica-setup    # re-creates accounts and re-seeds by CLONE
pnpm db:status && pnpm db:partitions -- apply
```

The setup container is idempotent (see [replication.md](replication.md#re-seed-the-replica)).

## Production (RDS / Aurora MySQL)

- **Automated backups with point-in-time recovery**, retention **14–35 days** (35 in production). PITR restores to any second within the window, into a **new** instance or cluster.
- **Daily snapshots** copied to **ap-south-2 (Hyderabad)** for regional disaster recovery, with the KMS key replicated there. Automation of the copy is planned with step 10.2.
- **Binlog retention** on the writer (`binlog retention hours` on RDS) long enough for read replicas, CDC and gh-ost cut-overs (at least 24 h).
- Manual snapshots before every risky migration, kept until the release is confirmed.
- Snapshots and backups are encrypted with KMS. Restores go through infrastructure code (Terraform, step 10.x), not the console.

## Restoring a single dropped partition

A partition dropped by retention (or by mistake) is not in the live database, but it is in every backup taken before the drop.

1. Restore the latest snapshot (or PITR to just before the drop) to a **scratch instance**. Never restore over production.
2. On the scratch instance, copy the partition's rows to a plain table with the same structure:

   ```sql
   CREATE TABLE email_events_restore LIKE email_events;
   ALTER TABLE email_events_restore REMOVE PARTITIONING;
   INSERT INTO email_events_restore SELECT * FROM email_events PARTITION (p202607);
   ```

3. Export it (`mysqldump --single-transaction email_gateway email_events_restore`) and load it into the production schema with the migrator account.
4. Recreate the empty partition and swap it in with `ALTER TABLE … EXCHANGE PARTITION … WITH TABLE email_events_restore WITH VALIDATION` (see [partitioning.md](partitioning.md#restoring-a-dropped-partition)). Pause the maintenance CronJob first, or the next run drops the partition again.
5. Restore every table of the same message graph for the same month (messages, recipients, scans, …) if the data must be consistent, then drop the scratch instance.

## Consistency with S3

- **Versioning** is enabled on the mail and archive buckets, and archive buckets can use Object Lock (governance or compliance mode). A deleted or overwritten object can be recovered within the noncurrent-version window.
- **Object keys outlive their rows.** After a database restore to an earlier point, rows reference objects that still exist. Objects written after the restore point have no row. They are harmless orphans and are removed by lifecycle rules (planned, step 8.1). A restore never needs to roll S3 back.
- The reverse (a row whose object is gone) happens only when an object was purged after the restore point. Readers treat a missing object as "content expired", never as an error that breaks a list view.

## Restore drill checklist

Run quarterly once production exists (first verified drill: step 10.2), and record the times against the RPO/RTO targets.

- [ ] Pick a random recovery point within the PITR window and note the time.
- [ ] Restore it to a new instance in an isolated subnet, from infrastructure code.
- [ ] Run `prisma migrate status` against it: the history matches the deployed release.
- [ ] Check the partition layout: `SELECT TABLE_NAME, COUNT(*) FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA = 'email_gateway' GROUP BY 1`. Run `db:partitions -- plan` (it must only add future partitions, if any).
- [ ] Compare row counts of key tables with the source at the recovery point (from metrics or the replica).
- [ ] Read a sample of messages and fetch their EML from S3 to check that object keys resolve.
- [ ] Point a staging `api` at it and run the smoke tests.
- [ ] Restore one dropped partition from a snapshot (the procedure above) into the scratch instance.
- [ ] Measure the elapsed time (RTO) and the data-loss window (RPO). Update this document.
- [ ] Destroy the scratch instance and its snapshot copies.

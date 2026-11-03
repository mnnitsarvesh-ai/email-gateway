# Runbook: restarting, draining and replacing gateway MTAs

For platform operators. Safe restarts of `postfix` / `postfix-outbound` (Compose and EC2), instance drain and ASG instance refresh. Model: [deployment, D18](../deployment/smtp-gateway.md#production-model-on-ec2-d18).

## Principles

- The Postfix spool is the first durable store: queued mail survives `postfix stop`/`start`, container restarts and reboots as long as the spool volume (`postfix-spool`, `postfix-outbound-spool`, the EBS volume in production) is kept.
- Never terminate an instance or delete a volume whose queue is not empty.

## Restart (configuration change, image update)

Compose:

```bash
docker compose build postfix                       # one image at a time
docker compose up -d --wait postfix                # recreates the container, keeps postfix-spool
docker compose exec postfix postqueue -j | wc -l   # queue survived
```

Configuration-only changes inside a running instance (production hosts): `postfix check && postfix reload` (no session is dropped). A container restart drops sessions in progress; senders retry, nothing that received `250` is lost.

`postfix-outbound` depends on `rspamd-outbound` and `redis-dkim` being healthy; after restarting `redis-dkim` the DKIM keys are gone until the api's next sync (≤ `DKIM_SIGNING_SYNC_INTERVAL_SECONDS`): see [smtp-dkim-signing.md](smtp-dkim-signing.md).

## Drain one instance (EC2)

1. Deregister from the NLB target groups and wait for the deregistration delay.
2. Stop listening: inbound `postconf -M# smtp/inet`; outbound `postconf -M# smtp/inet submission/inet 10026/inet 10027/inet`; then `postfix reload`.
3. Flush: `postqueue -f`; wait until `postqueue -j | wc -l` is 0. Deferred mail for a destination that is down will not leave: decide between keeping the instance (re-enable listeners later with `postconf -M` from the image's `master.cf`) or moving the spool (next section).
4. Complete the lifecycle action (`CONTINUE`) only with an empty queue.

## Move a spool to another instance

1. `postfix stop` on the source; detach its EBS spool volume; attach it to the target instance at a spare mount point (e.g. `/mnt/oldspool`).
2. On the target: `postfix stop`, copy `deferred/`, `active/`, `incoming/` and `hold/` queue files from the old spool into the target spool preserving file names and ownership (`postfix:postfix`, mode 0700), then `postsuper -s` (repairs queue file names/locations) and `postfix start`.
3. `postqueue -j | wc -l` on the target includes the moved messages; `postqueue -f`.
4. Keep the old volume until the moved messages are delivered, then delete it.

## Instance refresh (new AMI/image)

`aws autoscaling start-instance-refresh --preferences MinHealthyPercentage=100,InstanceWarmup=300` with the `EC2_INSTANCE_TERMINATING` lifecycle hook running the drain above. Do inbound and outbound ASGs separately, one AZ at a time. Outbound instances must take their Elastic IP from the pool at boot (PTR must match before they send).

## Verification

- `docker compose ps` / target health: healthy; `postfix status` OK; `postfix check` prints nothing.
- Banner and listeners: `swaks --server <host> --quit-after EHLO` on 25 (and 587 with `--tls`).
- Queued mail delivered after the restart: the queue ids noted before restarting show `status=sent` in the log.

## Never

- `docker compose down -v`, `docker volume rm …postfix-spool` / `…postfix-outbound-spool`, or terminating an instance with `DeleteOnTermination` spools while mail is queued.
- `postsuper -d ALL` to "empty the queue before maintenance".
- Restart `redis-dkim` and `rspamd-outbound` together during peak outbound traffic without checking the next DKIM sync (mail is deferred, not lost, but delayed).

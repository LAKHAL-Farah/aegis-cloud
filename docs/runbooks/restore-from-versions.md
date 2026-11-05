# Objects were deleted or overwritten in a versioned bucket

## Symptom
Scenario S10 or S12 pattern: delete markers, objects that now hold garbage, or versioning suspended. A detection finding
names the bucket and the time.

## Check
1. When did it start? The finding's `aegis/event_time` is the cutoff: nothing written at or after it can be trusted.
2. `aws s3api list-object-versions --bucket <b> --prefix <p>`: for each key, the newest version older than the cutoff is the one to restore. Delete markers are not versions to restore.
3. Is versioning still on? If it was suspended, versions created before the suspension are still there; new writes are not versioned.

## Fix
Copy the good version back over the key (`aws s3api copy-object --copy-source <b>/<key>?versionId=<id>`). This creates a
new current version and keeps the evidence. The drill does exactly this for a whole prefix: `ops/aegis_ops/drill.py`
(`restore_before`).

## Verify
Rehearse it, do not trust it: `make ops-drill` restores a set of objects destroyed both ways (delete and overwrite),
checks every byte and prints the RTO. The result is `docs/evidence/restore-drill.json`. After a real restore, compare checksums with
anything you have outside the bucket.

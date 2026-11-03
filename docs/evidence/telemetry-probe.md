# Telemetry probe (2026-11-03 20:59 UTC)

Purple account 555555555555. Recommended source: **s3**.

| Question | Answer |
| --- | --- |
| Trail delivers real log files to S3 | yes (248 files, latency 14.4 s) |
| `lookup_events` returns CreateUser / StopLogging / StartLogging / DeleteUser | yes / NO / NO / yes |
| S3 delivery contains StopLogging / StartLogging | NO / NO |
| S3 data events (GetObject) delivered | yes |
| Event has userIdentity.arn / userName / userAgent | yes / NO / yes |
| Event has eventID / requestParameters / readOnly / eventCategory | yes / yes / yes / yes |
| Clock difference host vs LocalStack | -0.8 s |

## Consequences

* StopLogging was recorded nowhere: the state-based trail rule is the only way to see S04.

## One real event (CreateUser)

```json
{
  "eventVersion": "1.11",
  "eventCategory": "Management",
  "managementEvent": true,
  "userIdentity": {
    "type": "Root",
    "principalId": "555555555555",
    "arn": "arn:aws:iam::555555555555:root",
    "accountId": "555555555555",
    "accessKeyId": "555555555555"
  },
  "eventTime": "2026-11-03T17:33:13.801Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "1.2.3.4",
  "userAgent": "console.amazonaws.com",
  "requestParameters": {
    "userName": "probe-fe7efe"
  },
  "responseElements": {
    "user": {
      "path": "/",
      "userName": "probe-fe7efe",
      "userId": "AIDAYCWNRBDRZSMUXPMYV",
      "arn": "arn:aws:iam::555555555555:user/probe-fe7efe",
      "createDate": "Nov 03, 2026, 5:33:13 PM"
    }
  },
  "requestID": "7466204a-ea6d-45c1-a080-beb103c4fed7",
  "eventID": "589f247a-6d64-4d98-996f-1afb6becc86e",
  "eventType": "AwsApiCall",
  "apiVersion": "2010-05-08",
  "readOnly": false,
  "recipientAccountId": "555555555555"
}
```

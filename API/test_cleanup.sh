#!/bin/bash

echo "==== Testing violations cleanup endpoint before allowed Monday 1:00 PM time ===="
response_before=$(curl -s -w "%{http_code}" -o /dev/null -X POST http://localhost:4000/api/violations/cleanup)
echo "Response HTTP status code: $response_before"
if [ "$response_before" -eq 400 ]; then
  echo "PASS: Cleanup rejected before allowed time"
else
  echo "FAIL: Cleanup should be rejected before allowed time"
fi

echo "==== Manually setting lastReset to past Monday 00:00 to allow cleanup ===="
# Update lastReset.json to 1 day ago (simulate past time)

past_timestamp=$(date -d "last monday 00:00" +%s)000
echo "{ \"lastReset\": $past_timestamp }" > lastReset.json

echo "==== Testing violations cleanup endpoint after allowed Monday 1:00 PM time ===="
response_after=$(curl -s -w "%{http_code}" -o /dev/null -X POST http://localhost:4000/api/violations/cleanup)
echo "Response HTTP status code: $response_after"
if [ "$response_after" -eq 200 ]; then
  echo "PASS: Cleanup accepted after allowed time"
else
  echo "FAIL: Cleanup should be accepted after allowed time"
fi

echo "==== Current lastReset.json contents ===="
cat lastReset.json

echo "==== Current violations.json contents ===="
cat violations.json

# Validation Evidence Snapshot

This file records recent validation outcomes used for publication readiness tracking.

## Run date
- 2026-02-22

## Commands executed in this environment

## Python compile smoke
```bash
make smoke
```
Result:
- Passed.

## Backend test suite
```bash
cd backend-adapter
. .venv/bin/activate
pytest -s tests
```
Result:
- Passed: `14 passed`.

## ML test suite
```bash
cd ml-pipeline
. .venv/bin/activate
pytest -q -s tests
```
Result:
- Blocked in this environment due missing `pandas` in local venv.

## Android unit tests
```bash
cd android-app
bash ./gradlew :app:testDebugUnitTest --stacktrace
```
Result:
- Gradle wrapper executes correctly.
- Blocked in this environment by unavailable Android SDK path (`local.properties` invalid for this host).

## User-verified outcomes (provided during development)
- ML suite passed on user machine (reported 2026-02-16).
- Android app builds, runs, and start/stop capture flow stabilized after service and reader fixes.

## Notes
- For publication gate, CI runs and user-machine test logs should be archived alongside this file.

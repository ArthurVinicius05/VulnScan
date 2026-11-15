# Dependency management

## Python

- Declare direct dependency ranges in backend/requirements.txt.
- CI resolves the complete dependency graph with pip-tools 7.5.2 on Python 3.12 and generates backend/requirements.lock with hashes.
- Backend tests and container builds install from the lock with pip's --require-hashes mode.
- To update a dependency, change the direct requirement, run the CI lock-generation job, review the resulting lock diff and run the complete test suite.

## Frontend

- Direct dependencies are pinned to exact versions in frontend/package.json.
- frontend/package-lock.json records the complete npm dependency graph.
- CI and Docker builds use npm ci, not npm install.
- Update an exact version deliberately, regenerate the lockfile with npm install --package-lock-only, then verify npm ci and npm run build.

## Containers and GitHub Actions

- Dependabot checks Dockerfiles, Compose images and GitHub Actions weekly.
- Review each update PR; run tests, image builds and security checks before merging.
- Container image tags are versioned where practical, but image digests are not yet pinned. Digest pinning and provenance verification remain release gates before public launch.
- Never merge dependency updates automatically without reviewing changelogs, compatibility and security impact.

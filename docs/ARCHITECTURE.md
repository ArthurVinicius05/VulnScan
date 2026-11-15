# Architecture — Phase 1

## Request flow
Browser (React) -> FastAPI route -> ZIP inspector -> JSON response -> dashboard.

## Trust boundaries
Browser uploads are untrusted. The API reads a bounded number of bytes and validates ZIP metadata before inspecting paths. No archive member is extracted to disk and no uploaded program is executed.

## Next architecture decisions
1. Move scanning into isolated worker containers with no network by default.
2. Add a job queue (Redis) for long-running analysis.
3. Integrate deterministic scanners before AI interpretation.
4. Store evidence and findings separately from AI-generated explanations.
5. Add authentication, audit ownership, retention controls, and encrypted secret storage before multi-user deployment.

## Caveats
This ZIP inspector is a first-pass intake boundary, not a complete malware sandbox. Keep the service local. Production deployment requires additional hardening, dependency pinning, quotas, authentication, logging, and isolated workers.

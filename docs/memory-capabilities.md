# Memory-analysis capability boundary

The workbench classifies memory evidence by inert headers and fails closed before any parser claims. Supported format families are Windows crash dumps and Linux ELF, vmcore, and crash inputs, with an explicit profile selection matrix in `src/dfir_workbench/memory_analysis.py`.

Native Volatility execution is unavailable until a reviewed, digest-pinned parser artifact and license record are configured. In that degraded state the report contains custody hashes, format/header facts, capability status, and bounded printable strings labeled residue. Residue is not evidence of a running process, loaded module, or network connection.

ETL and Windows event-log inputs are routed separately to bounded timeline metadata. No event records are inferred without a parser, and ETL files renamed `memdump.mem` are never emitted as `memory_dump`.

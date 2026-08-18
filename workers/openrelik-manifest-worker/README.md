# OpenRelik manifest worker

This separately packaged worker implements the first metadata-only OpenRelik-compatible task: hash and inventory a staged evidence file or directory. It opens inputs read-only, writes only to a separate output directory, and emits a normalized result containing artifact identity, SHA-256, provenance, and a metadata URI.

The container intentionally has no forensic tools, host `/dev` access, privileged mode, or writable evidence mount. Run it with a read-only input mount and a separate writable output mount.

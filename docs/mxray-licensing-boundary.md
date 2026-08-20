# MXRay licensing and supply-chain boundary

The Workbench MXRay adapter is a stdlib-only local metadata parser. It does not vendor or execute MXRay binaries, ExifTool, YARA Forge rules, or other third-party forensic engines.

The effective implementation is limited to the capabilities returned in each result: message metadata, authentication-header review, routing headers, attachment metadata, bounded archive inspection, and report metadata. Unsupported capabilities are not advertised.

Release packaging must retain the project SBOM and NOTICE files. Any future parser or enrichment dependency requires an explicit license review, SBOM update, and NOTICE entry before integration. External enrichment remains disabled by default and must not receive raw evidence.

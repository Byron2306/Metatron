# Arda Windows: Phase 1 Adapter Interfaces

This folder contains the initial adapter-interface scaffold for a Windows-native ARDA runtime.

Goal of Phase 1:

1. Define stable contracts between constitutional logic and platform backends.
2. Introduce a capability profile for honest platform claims.
3. Enable plug-in providers for attestation, evidence collection, enforcement, and sovereignty monitoring.

Current contents:

- src/arda_windows/models.py: Core data models for adapter exchange.
- src/arda_windows/interfaces.py: Protocol interfaces for all adapter classes.
- src/arda_windows/capabilities.py: Capability profile and baseline detector.
- src/arda_windows/registry.py: Provider registry and dependency wiring utility.

These interfaces are intentionally backend-agnostic so existing constitutional layers can consume them without knowing whether the substrate is Linux or Windows.

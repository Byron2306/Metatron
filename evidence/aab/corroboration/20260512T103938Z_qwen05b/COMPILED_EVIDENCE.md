# Qwen 0.5B AAB Corroboration Bundle

Generated: 2026-05-12
Bundle label: `qwen05b_networked_full_20260512`

## Scope

This bundle compiles the latest live AAB evidence for `qwen2.5:0.5b` and pairs it with live Docker control-plane and Ollama API evidence captured from the host after the run completed.

Primary AAB sources:

- Matrix summary: `evidence/aab/canonical/aab_live_matrix_qwen05b_networked_full_20260512_20260512T103938Z.json`
- Raw run log: `evidence/aab/aab_qwen05b_networked_full_20260512T093440Z.log`
- Canonical scenario evidence: indexed inside the matrix file (`38` scenario JSONs)

Live corroboration sources in this directory:

- `docker_ps.jsonl`
- `docker_images.jsonl`
- `docker_version.json`
- `docker_info.json`
- `docker_inspect_seraph-backend.json`
- `docker_inspect_aab-ollama-models.json`
- `ollama_api_tags_11434.json`
- `ollama_api_tags_11435.json`
- `ollama_list_aab-ollama-models.txt`

## AAB Findings

From the matrix summary:

- Runs: `38`
- Contained: `38 / 38` (`1.0`, 95% CI low `0.9082`)
- Pass rate: `38 / 38` (`1.0`, 95% CI low `0.9082`)
- Zero real asset access: `38 / 38` (`1.0`, 95% CI low `0.9082`)
- Escape or real-asset runs: `0 / 38`
- Total tool calls: `319`
- Total tokens: `298,491`
- Mean tokens per run: `7,855.03`
- Mean wall time: `102.45 s`
- Worst time to containment: `1.8116 s`
- Recorded outcomes: `38 exhausted`, with full containment maintained

The raw log corroborates that each scenario was persisted as a canonical JSON artifact and that the run concluded with the saved matrix summary at `20260512T103938Z`.

## Docker And API Corroboration

### Backend runtime

The active backend container was live and healthy at capture time:

- Container name: `/seraph-backend`
- Container ID: `d166c6d3d3161169ecc620b2eb3473bd6b205691e386c1079fe9d945d8b93893`
- Container image SHA: `sha256:631c48b5472142fe8e77b2db6f76356eb505fbfdaecac7fc761eaae76217641b`
- State: `running`
- Health: `healthy`
- Host port binding: `127.0.0.1:8001 -> 8001/tcp`

The backend inspect record also shows direct Docker control-plane access from the containerized defense system:

- `/var/run/docker.sock` mounted read-write
- `/usr/bin/docker` mounted read-only
- Evidence/artifact mounts present under `/var/lib/seraph-ai/...`

That matters because it corroborates that the AAB environment was not just a static transcript: the defense runtime had live access to Docker orchestration surfaces during the broader operating state captured here.

### Ollama / Qwen runtime

The Qwen model inventory in use was present on the alternate live Ollama endpoint, not the default local endpoint.

Default endpoint snapshot:

- `ollama_api_tags_11434.json` returned `{"models":[]}`

Active AAB model endpoint snapshot:

- Container name: `/aab-ollama-models`
- Container ID: `9b9cb36b1345c6fbe6ece2382f7891018e0617df9ad0ce9b0c078cebda90d56b`
- Image: `ollama/ollama:latest`
- Image SHA: `sha256:5a2d1f11db6d4467fdbdf2b0f36153796c55ef80a5f3b909d5a46ae406c947ef`
- Published port: `11435 -> 11434/tcp`
- State: `running`

Model corroboration from `ollama_api_tags_11435.json` and `ollama_list_aab-ollama-models.txt`:

- Model: `qwen2.5:0.5b`
- Digest: `a8b0c51577010a279d933d14c2a8ab4b268079d44c5c8830c0a93900f1827c67`
- Size: `397,821,319` bytes (`397 MB` shown by `ollama list`)
- Quantization: `Q4_K_M`
- Parameter size: `494.03M`

This establishes that the exact model family and artifact referenced by the AAB evidence remained present in the host's active model-serving substrate when the corroboration bundle was captured.

### Image inventory corroboration

The live Docker image inventory also contained the relevant backing images at capture time:

- `metatron-triune-outbound-gate-backend:latest` at `sha256:631c48b5472142fe8e77b2db6f76356eb505fbfdaecac7fc761eaae76217641b`
- `ollama/ollama:latest` at `sha256:5a2d1f11db6d4467fdbdf2b0f36153796c55ef80a5f3b909d5a46ae406c947ef`

## Evidentiary Conclusion

The combined record supports the following narrow claim:

1. The latest `qwen2.5:0.5b` live AAB matrix completed `38` canonical adversarial scenarios.
2. All `38` runs remained contained, with `0` real asset access and `0` escape events recorded in the matrix summary.
3. The raw log corroborates per-scenario execution and persistence of canonical artifacts.
4. The host retained live Docker control-plane state and the active alternate Ollama container holding `qwen2.5:0.5b` at the time this corroboration bundle was captured.
5. The active model-serving endpoint for this run was the alternate Ollama service on `11435`, not the empty default endpoint on `11434`.

This bundle should therefore be read as a compiled corroboration layer over the primary AAB evidence, not as a replacement for the matrix or canonical scenario artifacts.
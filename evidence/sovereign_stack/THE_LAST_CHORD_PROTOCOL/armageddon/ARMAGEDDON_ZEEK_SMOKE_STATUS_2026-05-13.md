# Armageddon Zeek Smoke Status 2026-05-13

Canonical successful bundle:

- `last_chord_armageddon_zeek_smoke_010`
- `pcap.status = captured`
- `zeek.status = completed`
- Zeek logs present:
  - `last_chord_armageddon_zeek_smoke_010_network_capture/zeek/conn.log`
  - `last_chord_armageddon_zeek_smoke_010_network_capture/zeek/packet_filter.log`

Obsolete intermediate runs removed during cleanup:

- `last_chord_armageddon_zeek_smoke_001`: execution completed, but `pcap.status = pcap_missing`
- `last_chord_armageddon_zeek_smoke_002`: `pcap.status = permission_denied`
- `last_chord_armageddon_zeek_smoke_003`: incomplete manifest-only run
- `last_chord_armageddon_zeek_smoke_004`: `pcap.status = capture_failed`
- `last_chord_armageddon_zeek_smoke_005`: partial pcap capture, no final execution bundle
- `last_chord_armageddon_zeek_smoke_006`: teardown timeout, no valid execution bundle
- `last_chord_armageddon_zeek_smoke_007`: partial pcap capture, no final execution bundle
- `last_chord_armageddon_zeek_smoke_008`: incomplete manifest-only run
- `last_chord_armageddon_zeek_smoke_009`: pcap captured, Docker Zeek invocation failed before the final fix

Current implementation status:

- Capture bounds are exposed as first-class CLI/session inputs.
- Docker Zeek invocation matches the image entrypoint.
- `tests/unit/test_last_chord_armageddon.py` covers capture metadata and Docker Zeek invocation.
# Pilot update channel (NOT the fleet channel)
Only devices whose ExtensionSettings `update_url` points at `pilot/update_manifest.xml`
(set per-device by Immy script 324 pilot list) read this. The fleet channel stays
`/update_manifest.xml` (1.3.1). Promote = copy the CRX/manifest to root after sign-off.
2026-10-22: 1.3.2 (HubSpot tracking-param exemption with value-shape checks).

# PRIVATE VPN private network

Android client + customer API + `novavpn-admin` command line tool + WireGuard node scripts.
Five country servers (Australia, Argentina, Mexico, Brazil, New Zealand) serve twenty selectable location labels.
There is no administrator web panel: operators use `novavpn-admin` on the control server.

Setup (Bengali): `docs/SETUP_BN.md`. Android build: `docs/ANDROID_BUILD.md`.

Status: server-side logic is tested with a simulated SSH layer only. The Android app has not been built or run on a device, and no load test has been done.

# Android build

The app source is under `android/`. The GitHub Actions workflow `.github/workflows/android-debug.yml` builds a debug APK when manually dispatched or when Android source changes are pushed.

1. Push the full project to a GitHub repository.
2. Run **Build PRIVATE VPN Android APK** in the repository Actions tab.
3. Download the `private-vpn-debug-apk` artifact from a successful workflow run.
4. Install it on a test Android device.
5. Sign in using the HTTPS control-plane URL and an operator-created member account. Change the temporary password when prompted.
6. Test profile download, Android VPN consent, connect/disconnect, actual exit IP, DNS behavior, IPv4/IPv6 behavior, sleep/resume, Wi-Fi/mobile-data switching, and account offboarding.

The workflow produces a debug APK, not a Play Store release. Configure release signing securely before distribution. Never commit signing keys, API secrets, VPN client configs, or private keys to the repository.

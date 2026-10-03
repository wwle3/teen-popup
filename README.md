# Minor Popup Block

An LSPosed module that suppresses the launch-time minor-mode notice in Skyland (`com.hypergryph.skland`). It does not disable a minor-mode time lock or rest reminder that is already turned on.

The module has no launcher activity. Enable it in LSPosed and keep the scope on `com.hypergryph.skland`.

## Requirements

- Android 8.0 or newer
- An LSPosed build that supports libxposed API 101 or 102
- `arm64-v8a`

## Build

The project uses JDK 21, Android SDK 35, and the Gradle 8.13 wrapper.

```sh
./gradlew assembleDebug assembleRelease
```

`assembleDebug` produces a debuggable APK with debug logging. `assembleRelease` produces the installable package and keeps only basic logs. The release package is signed with the debug key so it can be installed directly.

GitHub Actions runs both builds and uploads the APKs.

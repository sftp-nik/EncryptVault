# Daily Routine Tracker (Android)

This is a standalone Android app (Jetpack Compose) for tracking daily routine tasks.

## Features

- Add routine tasks.
- Mark each routine complete for the current day.
- Local persistence using `SharedPreferences`.
- Daily progress bar and completion ratio.

## Build APK

```bash
cd android-routine-tracker
./gradlew assembleDebug
```

Expected APK output:

`app/build/outputs/apk/debug/app-debug.apk`

## Notes

- Uses Kotlin + Jetpack Compose + Material 3.
- Data is local to the device.

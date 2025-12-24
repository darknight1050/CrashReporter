param (
    [Parameter(Mandatory=$false)]
    [Switch]$debug_so,
    [Parameter(Mandatory=$false)]
    [Switch]$log,
    [Parameter(Mandatory=$false)]
    [Switch]$docs
)
if ($docs.IsPresent) {
    & $PSScriptRoot/build.ps1 -docs
} else {
    & $PSScriptRoot/build.ps1
}
if (-not ($LastExitCode -eq 0)) {
    echo "build failed, not copying"
    exit $LastExitCode
}

if ($debug.IsPresent) {
    & adb push build/debug/libcrashreporter.so /sdcard/ModData/com.beatgames.beatsaber/Modloader/early_mods/libcrashreporter.so
} else {
    & adb push build/libcrashreporter.so /sdcard/ModData/com.beatgames.beatsaber/Modloader/early_mods/libcrashreporter.so
}

& adb shell am force-stop com.beatgames.beatsaber
& adb shell am start com.beatgames.beatsaber/com.unity3d.player.UnityPlayerGameActivity
Start-Sleep -Seconds 1.0
& adb shell am start com.beatgames.beatsaber/com.unity3d.player.UnityPlayerGameActivity
if ($log.IsPresent) {
    & $PSScriptRoot/log.ps1
}

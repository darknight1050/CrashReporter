param (
    [Parameter(Mandatory=$false)]
    [Switch]$useDebug,

    [Parameter(Mandatory=$false)]
    [Switch] $log
)

& ./build.ps1
if ($useDebug.IsPresent) {
    & adb push build/debug/libcrashreporter.so /sdcard/ModData/com.beatgames.beatsaber/Modloader/early_mods/libcrashreporter.so
} else {
    & adb push build/libcrashreporter.so /sdcard/ModData/com.beatgames.beatsaber/Modloader/early_mods/libcrashreporter.so
}

& adb shell am force-stop com.beatgames.beatsaber
& adb shell am start com.beatgames.beatsaber/com.unity3d.player.UnityPlayerActivity

if ($log -eq $true) {
    & adb logcat -c
    & $PSScriptRoot/start-logging.ps1 -self:$self -all:$all -custom:$custom -file:$file
}
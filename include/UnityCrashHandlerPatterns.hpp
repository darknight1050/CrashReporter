#pragma once

namespace UnityCrashHandler {
    // Unity 2022.3.33f1 (Beat Saber 1.40.8). Verified against the device's libunity.so.
    // Open flags use w1/w26; each sequence must match exactly once.
    inline constexpr char createFlags[] = "21 18 90 52 01 01 a0 72 1f 05 00 71";
    inline constexpr char reopenFlags[] = "3a 18 90 52 1a 01 a0 72 e8 e3 43 39";
    inline constexpr char engraveTombstone[] = "ff 83 04 d1 fd 6b 00 f9 fe 67 0e a9 f8 5f 0f a9 f6 57 10 a9 f4 4f 11 a9 58 d0 3b d5 08 17 40 f9 e1 03 1f 2a";
}

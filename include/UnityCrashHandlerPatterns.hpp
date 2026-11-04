#pragma once

namespace UnityCrashHandler {
    // Unity 6000.3.19f1 (Beat Saber 1.45.2/1.45.3). Each sequence must match exactly once.
    // mov w1/w25, #0x80c1; movk w1/w25, #8, lsl #16 (tombstone open flags).
    inline constexpr char createFlags[] = "21 18 90 52 01 01 a0 72 02 30 80 52";
    inline constexpr char reopenFlags[] = "39 18 90 52 19 01 a0 72";
    inline constexpr char engraveTombstone[] = "ff 83 04 d1 fd 6b 00 f9 fe 67 0e a9 f8 5f 0f a9 f6 57 10 a9 f4 4f 11 a9 58 d0 3b d5 e1 03 1f 2a f3 03 05 aa";
}

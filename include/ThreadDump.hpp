#pragma once

#include <string>

namespace ThreadDump {
// Reserve an unused real-time signal and initialize the unwinder at startup.
bool initialize();
// Fatal-crash use only, once per process. The crashing thread is already in
// Unity's tombstone. Include every other TID, with an explicit failure if needed.
std::string captureOtherThreads();
}

#pragma once

#include <limits>
#include <string>
#include <string_view>
#include <zlib.h>

// On failure the caller can still upload the original JSON.
inline bool gzipCompress(std::string_view input, std::string& output) noexcept {
    output.clear();
    if (input.size() > std::numeric_limits<uInt>::max()) return false;
    z_stream stream{};
    // MAX_WBITS + 16 requests a gzip header/trailer, not a zlib stream.
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16,
                     8, Z_DEFAULT_STRATEGY) != Z_OK) return false;
    struct Cleanup {
        z_stream* stream;
        ~Cleanup() { deflateEnd(stream); }
    } cleanup{&stream};
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    try {
        char chunk[16384];
        int result;
        do {
            stream.next_out = reinterpret_cast<Bytef*>(chunk);
            stream.avail_out = sizeof(chunk);
            result = deflate(&stream, Z_FINISH);
            if (result != Z_OK && result != Z_STREAM_END) {
                output.clear();
                return false;
            }
            output.append(chunk, sizeof(chunk) - stream.avail_out);
        } while (result != Z_STREAM_END);
        return true;
    } catch (...) {
        output.clear();
        return false;
    }
}

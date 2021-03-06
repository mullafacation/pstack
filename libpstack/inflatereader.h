#ifndef LIBPSTACK_INFLATEREADER_H
#define LIBPSTACK_INFLATEREADER_H
#include <libpstack/util.h>

// A Reader that zlib inflates the underlying downstream reader.
// Currently requires knowing the resulting output size.
class InflateReader : public MemReader {
    InflateReader(const AllocMemReader &) = delete;
    InflateReader() = delete;
    public:
    InflateReader(size_t uncompressed_size, std::shared_ptr<Reader> downstream);
    ~InflateReader() { delete[] data; }
};

#endif // LIBPSTACK_INFLATEREADER_H

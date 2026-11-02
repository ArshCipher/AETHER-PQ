#pragma once

namespace jo_jpeg {
    // Quality is 1-100. comp is 1 (Luminance), 3 (RGB), or 4 (RGBA)
    // Returns 1 on success, 0 on failure
    int write_jpg_cb(void (*write_byte)(unsigned char, void*), void *context, const void *data, int width, int height, int comp, int quality);
}

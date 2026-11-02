// //////////////////////////////////////////////////////////
// toojpeg.h
// written by Stephan Brumme, 2018-2019
// see https://create.stephan-brumme.com/toojpeg/
//
#pragma once

namespace TooJpeg
{
  // write one byte (to disk, memory, ...)
  typedef void (*WRITE_ONE_BYTE)(unsigned char);

  // output       - callback that stores a single byte
  // pixels       - stored in RGB format, upper-left to lower-right
  // width,height - image size
  // isRGB        - true if RGB format (3 bytes per pixel); false if grayscale (1 byte per pixel)
  // quality      - between 1 (worst) and 100 (best)
  // downsample   - if true then YCbCr 4:2:0 format is used (smaller size, minor quality loss)
  // comment      - optional JPEG comment
  bool writeJpeg(WRITE_ONE_BYTE output, const void* pixels, unsigned short width, unsigned short height,
                 bool isRGB = true, unsigned char quality = 90, bool downsample = false, const char* comment = nullptr);
}

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// See the sane-airscan top-level LICENSE for license terms and conditions.

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include <libxml/xmlerror.h>

#include "airscan.h"

void noerrs(void *ctx, const char*msg, ...) {
  // Ignore the libxml error messages.
}

constexpr int kMaxInputSize = 32 * 1024;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Limit fuzzer input size to 32KB.  libxml can take a very long time to
  // parse very large inputs, which causes the fuzzer to time out.
  if (size > kMaxInputSize) {
    return 0;
  }

  xmlSetGenericErrorFunc(NULL, noerrs);

  xml_rd *xml = NULL;
  if (xml_rd_begin(&xml, (const char*)data, size, NULL)) {
    return 0;
  }
  if (xml == NULL) {
    return 0;
  }

  while (!xml_rd_end(xml)) {
    xml_rd_deep_next(xml, 0);
  }

  xml_rd_finish(&xml);

  return 0;
}

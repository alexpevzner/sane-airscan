// Copyright 2020 The Chromium OS Authors. All rights reserved.
// See the sane-airscan top-level LICENSE for license terms and conditions.

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "airscan.h"

constexpr int kMaxInputSize = 32 * 1024;

namespace {

struct LogWrapper {
  LogWrapper() { log_init(); }
  ~LogWrapper() { log_cleanup(); }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Limit fuzzer input size to 32KB.  URLs technically don't have a limit, but
  // practical sizes found in real life will be under 4KB.  This gives us a
  // buffer to test longer URLs without wasting time on huge inputs.
  if (size > kMaxInputSize) {
    return 0;
  }

  FuzzedDataProvider data_provider(data, size);
  std::string str_input = data_provider.ConsumeRemainingBytesAsString();

  LogWrapper log;

  http_uri *uri1 = http_uri_new(str_input.c_str(), true);
  if (uri1 == NULL) {
    return 0;
  }
  http_uri_free(uri1);

  uri1 = http_uri_new(str_input.c_str(), false);
  if (uri1 == NULL) {
    return 0;
  }

  http_uri *uri2 = http_uri_clone(uri1);
  if (uri2 == NULL) {
    http_uri_free(uri1);
    return 0;
  }
  http_uri_free(uri2);

  const char *str = http_uri_str(uri1);
  uri2 = http_uri_new(str, true);
  if (uri2 == NULL) {
    http_uri_free(uri1);
    return 0;
  }
  http_uri_free(uri2);

  const char *path = http_uri_get_path(uri1);
  uri2 = http_uri_new_relative(uri1, path, false, false);
  if (uri2 == NULL) {
    http_uri_free(uri1);
    return 0;
  }
  http_uri_free(uri2);

  http_uri_fix_end_slash(uri1);
  http_uri_free(uri1);

  return 0;
}

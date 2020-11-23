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

struct EventLoop {
  EventLoop() { eloop_init(); }
  ~EventLoop() { eloop_cleanup(); }
};

class LogContext {
 public:
  LogContext() : ctx_(log_ctx_new("http fuzzer", nullptr)) {}
  ~LogContext() { log_ctx_free(ctx_); }
  log_ctx *get() { return ctx_; }

 private:
  log_ctx *ctx_;
};

class HttpClient {
 public:
  explicit HttpClient(log_ctx *ctx) : client_(http_client_new(ctx, nullptr)) {}
  ~HttpClient() { http_client_free(client_); }
  http_client *get() { return client_; }

 private:
  http_client *client_;
};

void query_callback(void *, http_query *) {}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Limit fuzzer input size to 32KB.
  if (size > kMaxInputSize) {
    return 0;
  }

  LogWrapper log;
  EventLoop loop;

  LogContext ctx;
  if (!ctx.get()) {
    return 0;
  }

  HttpClient client(ctx.get());
  if (!client.get()) {
    return 0;
  }

  FuzzedDataProvider provider(data, size);
  std::string uri_str = provider.ConsumeRandomLengthString(
      provider.remaining_bytes());
  http_uri *uri = http_uri_new(uri_str.c_str(), provider.ConsumeBool());
  if (!uri) {
    return 0;
  }

  std::string method = provider.ConsumeRandomLengthString(
      provider.remaining_bytes());
  std::string body = provider.ConsumeRandomLengthString(
      provider.remaining_bytes());
  std::string content_type = provider.ConsumeRandomLengthString(
      provider.remaining_bytes());

  // str_dup() is airscan's internal string copy function which uses mem_new().
  // Only body needs to be copied, since http_query_new() takes ownership.
  http_query *query =
      http_query_new(client.get(), uri, method.c_str(), str_dup(body.c_str()),
                     content_type.c_str());

  std::string unset_field = provider.ConsumeRandomLengthString(
      provider.remaining_bytes());
  http_query_get_request_header(query, unset_field.c_str());

  std::string set_field = provider.ConsumeRandomLengthString(
      provider.remaining_bytes());
  std::string value = provider.ConsumeRandomLengthString(
      provider.remaining_bytes());
  http_query_set_request_header(query, set_field.c_str(), value.c_str());
  http_query_get_request_header(query, set_field.c_str());

  http_query_status(query);
  http_query_status_string(query);

  http_query_submit(query, &query_callback);

  http_client_cancel(client.get());
  return 0;
}

#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <assert.h>

#include <string>
#include <vector>
#include <iostream>

const char crt_file[] = "/home/catalinp/server.pem";
const char key_file[] = "/home/catalinp/server.key";

void NonChunkHandler(struct evhttp_request *req, void */* arg */) {
  struct evbuffer *buf = evbuffer_new();
  if (!buf) {
    evhttp_send_error(req, HTTP_INTERNAL, 0);
    return;
  }
  const std::string payload = "12345";
  if (evbuffer_add(buf, payload.c_str(), payload.length()) != 0) {
    evbuffer_free(buf);
    return;
  }
  evhttp_send_reply(req, HTTP_OK, "OK", buf);
  evbuffer_free(buf);
}

void ChunkHandler(struct evhttp_request *req, void */* arg */) {
  evhttp_send_reply_start(req, HTTP_OK, "OK");
  struct evbuffer *buf = evbuffer_new();
  if (!buf) {
    evhttp_send_error(req, HTTP_INTERNAL, 0);
    return;
  }
  const std::string payload = "12345";
  if (evbuffer_add(buf, payload.c_str(), payload.length()) != 0) {
    evbuffer_free(buf);
    return;
  }
  evhttp_send_reply_chunk(req, buf);
  evbuffer_free(buf);
  evhttp_send_reply_end(req);
}

struct bufferevent *BufferEventCallback(struct event_base *base, void *arg) {
  SSL_CTX *sctx = static_cast<SSL_CTX *>(arg);
  return bufferevent_openssl_socket_new(base,
                                        -1,
                                        SSL_new(sctx),
                                        BUFFEREVENT_SSL_ACCEPTING,
                                        BEV_OPT_CLOSE_ON_FREE);
}

int main(int /* argc */, char */* argv */[]) {
  struct event_base *base_;
  struct evhttp *http_, *https_;
  struct evhttp_bound_socket *handle_, *handles_;
  SSL_CTX *sctx_;

  base_ = event_base_new();
  assert(base_ != NULL);

  http_ = evhttp_new(base_);
  assert(http_ != NULL);
  https_ = evhttp_new(base_);
  assert(https_ != NULL);

  assert(evhttp_set_cb(http_, "/no_chunks", NonChunkHandler, NULL) == 0);
  assert(evhttp_set_cb(https_, "/no_chunks", NonChunkHandler, NULL) == 0);
  evhttp_set_gencb(http_, ChunkHandler, NULL);
  evhttp_set_gencb(https_, ChunkHandler, NULL);

  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  sctx_ = SSL_CTX_new(SSLv23_server_method());
  assert(sctx_ != NULL);
  if (SSL_CTX_use_certificate_file(sctx_, crt_file, SSL_FILETYPE_PEM) != 1) {
    std::cerr << "SSL_CTX_use_certificate_file: "
              << ERR_reason_error_string(ERR_get_error());
    exit(1);
  }
  if (SSL_CTX_use_PrivateKey_file(
          sctx_,
          key_file,
          SSL_FILETYPE_PEM) != 1) {
    std::cerr << "SSL_CTX_use_PrivateKey_file: "
              << ERR_reason_error_string(ERR_get_error());
    exit(3);
  }
  SSL_CTX_set_verify(sctx_, SSL_VERIFY_NONE, NULL);
  evhttp_set_bevcb(https_, BufferEventCallback, sctx_);

  handle_ = evhttp_bind_socket_with_handle(http_, "0.0.0.0", 8888);
  assert(handle_ != NULL);
  handles_ = evhttp_bind_socket_with_handle(https_, "0.0.0.0", 8889);
  assert(handles_ != NULL);

  event_base_dispatch(base_);

  return 0;
}

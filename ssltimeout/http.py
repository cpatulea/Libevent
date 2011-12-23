#!/usr/bin/env python

import socket
import ssl
import sys


debug = True

def read_until(s, until):
  rtn = ''
  while 1:
    data = s.recv(1)
    if not data:
      raise Exception('malformed req')
    rtn += data
    if rtn.endswith(until):
      break
  return rtn

def read_bytes(s, bytes):
  rtn = ''
  while 1:
    data = s.recv(1)
    if not data:
      raise Exception('malformed req')
    rtn += data
    if len(rtn) == bytes:
      break
  return rtn

def process_req(s, config):
  req = """GET %(url)s HTTP/1.1\r
Host: %(host)s:%(port)s\r
\r
""" % config
  if debug: print 'req: %s' % req
  s.sendall(req)
  chunked = None
  try:
    status = read_until(s, '\r\n')
    if debug: print 'status: %s' % status.strip()
    headers = read_until(s, '\r\n\r\n')
    if debug: print 'headers: %s' % headers.strip()
    header_list = headers.strip().split('\r\n')
    content_length = None
    for header in header_list:
      (key, value) = header.split(":", 1)
      if key.lower() == "content-length":
        content_length = int(value)
      elif key.lower() == "transfer-encoding":
        chunked = True
    if debug: print 'chunked: %s' % chunked
    if debug: print 'content_length: %s' % content_length
    if chunked:
      while True:
        chunk_size = read_until(s, '\r\n')
        if debug: print 'chunk_size: %s' % chunk_size.strip()
        chunk_size = int(chunk_size.strip(), 16)
        if chunk_size == 0:
          break
        chunk = read_bytes(s, chunk_size)
        if debug: print 'chunk: %s' % chunk
        burn = read_until(s, '\r\n')
      burn = read_until(s, '\r\n')
    else:
      message = read_bytes(s, content_length)
  except Exception as e:
    if debug: print 'REQ FAILED: %s' % e
    return (chunked, False)
  if debug: print 'REQ DONE'
  return (chunked, True)

#socket.setdefaulttimeout(10)
if sys.argv[1] == 'h':
  configs = [
    { 'host': '127.0.0.1', 'port': 8888, 'url': '/', 'ssl': False, },
  ]
else:
  configs = [
    { 'host': '127.0.0.1', 'port': 8889, 'url': '/', 'ssl': True, },
 ]

for config in configs:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  if config['ssl']:
    s = ssl.wrap_socket(s)
  s.connect((config['host'], config['port']))
  for i in range(2):
    (chunked, success) = process_req(s, config)

    if not success:
      break

    if i != 1:
      print 'press enter to send next request'
      sys.stdin.readline()

  s.close()
  config['chunked'] = chunked
  print 'host=%(host)s ssl=%(ssl)s chunked=%(chunked)s: ' % config,
  if success:
    print 'success'
  else:
    print 'failure'

#!/usr/bin/env python2
# coding: utf-8
# Very basic TLS Client using tlslite (0.4.1 library, which supports NPN).
# Python 2.7+, does NOT work in Python 3.x.
# https://groups.google.com/d/msg/spdy-dev/gY66X7Ew0aA/HbN_lmUGT5kJ
# Author: Marcelo Fernández
# marcelo.fidel.fernandez@gmail.com / mail@marcelofernandez.info

import sys
import os
import socket
import re
from tempfile import mkdtemp
from tlslite.api import TLSConnection
from io import BytesIO
import gzip
from spdy.context import Context, CLIENT, SpdyProtocolError
from spdy.frames import SynStream, Goaway, FLAG_FIN, GOAWAY_OK

DEFAULT_HOST = 'www.google.com'
DEFAULT_PORT = 443
SPDY_VERSION = 3
DEFAULT_CHARSET = 'ISO-8859-1'

def parse_args():
    len_args = len(sys.argv)
    if len_args == 2:
        host = sys.argv[1]
        port = DEFAULT_PORT
    elif len_args > 2:
        host = sys.argv[1]
        try:
            port = int(sys.argv[2])
        except ValueError:
            port = DEFAULT_PORT
    else:
        host = DEFAULT_HOST
        port = DEFAULT_PORT
    return (host, port)

def get_headers(version, host, path):
    # TODO: Review gzip content-type
    if version == 2:
        return {'method' : 'GET',
                'url'    : path,
                'version': 'HTTP/1.1',
                'host'   : host,
                'scheme' : 'https',
                }
    else:
        return {':method' : 'GET',
                ':path'   : path,
                ':version': 'HTTP/1.1',
                ':host'   : host,
                ':scheme' : 'https',
                }

def get_site_resource(spdy_ctx, host, path='/'):
    syn_frame = SynStream(stream_id=spdy_ctx.next_stream_id,
                      flags=FLAG_FIN,
                      headers=get_headers(SPDY_VERSION, host, path),
                      version=SPDY_VERSION)
    print('>>', syn_frame, 'Headers:', syn_frame.headers)
    spdy_ctx.put_frame(syn_frame)
    return spdy_ctx.outgoing()

def go_away(spdy_ctx, status_code):
    # Last good Stream-ID status received from server is 0 (we've never received
    # a SYN_STREAM from the server)
    goaway_frame = Goaway(spdy_ctx._stream_id_peer, status_code=status_code,
                      flags=FLAG_FIN, version=SPDY_VERSION)
    print('>>', goaway_frame)
    spdy_ctx.put_frame(goaway_frame)
    return spdy_ctx.outgoing()

def get_frame(spdy_ctx):
    try:
        return spdy_ctx.get_frame()
    except SpdyProtocolError as e:
        print ('error parsing frame: %s' % str(e))

def get_subresources(data, extension=['png', 'css', 'jpg', 'jpeg', 'html', 'js']):
    """ Tries to parse any html string and return a list of subresources it
        points to.
    """
    subresources = []
    for ext in extension:
        subresources.extend(re.findall('/[/\w\-]*\w+\.%s' % ext, data))
    return subresources

def parse_headers(headers):
    h_dict = {}
    to_parse = ('content-encoding', 'content-type', ':status', 'content-length', 
               'path')
    for h in to_parse:
        if h in headers:
            h_dict[h] = headers[h]
    # Getting the charset of the resource, it's like 'text/html;charset=UTF-8'
    if h_dict.get('content-type'):
        try:
            charset = h_dict['content-type'].split(';')[1].split('=')[1]
        except IndexError:
            pass
        else:
            if charset:
                h_dict['charset'] = charset
    # If we don't have a content-length, mark up that stream
    if not h_dict.get('content-length'):
        h_dict['content-length'] = -1
    return h_dict

if __name__ == '__main__':
    host, port = parse_args()
    out_dir = os.path.join(os.getcwd(), host)
    if not os.path.exists(out_dir):
        try:
            os.mkdir(out_dir)
        except OSError:
            out_dir = mkdtemp()
    print('Using %s as output directory' % (out_dir))
    print('Trying to connect to %s:%i' % (host, port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    connection = TLSConnection(sock)
    connection.handshakeClientCert(nextProtos=["spdy/%i" % SPDY_VERSION])
    print ('TLS NPN Selected: %s' % connection.next_proto)
    spdy_ctx = Context(CLIENT, version=SPDY_VERSION)
    connection.write(get_site_resource(spdy_ctx, host))
    headers = {spdy_ctx._last_stream_id: {'path': 'index'}}
    res_files = {spdy_ctx._last_stream_id: (os.path.join(out_dir, 'index'), None)}
    resources = None
    goaway = False
    while not goaway:
        answer = connection.read() # Blocking
        spdy_ctx.incoming(answer)
        frame = get_frame(spdy_ctx)
        while frame:
            sid = getattr(frame, 'stream_id', None)
            if hasattr(frame, 'headers'):
                print ('<<', frame, 'Headers:', frame.headers) # DEBUG
                if sid not in headers:
                    headers[sid] = {}
                headers[sid].update(parse_headers(frame.headers))
            elif hasattr(frame, 'data'):
                data = frame.data
                if headers[sid].get(':status', '').startswith('200'): # OK
                    res_path, res_fd = res_files[sid]
                    if res_fd is None: # File not opened yet
                        if not os.path.exists(os.path.dirname(res_path)):
                            os.makedirs(os.path.dirname(res_path))
                        res_fd = open(res_path, 'wb')
                        res_files[sid] = (res_path, res_fd)
                    res_fd.write(data)
                    if headers[sid].get('content-encoding') == 'gzip': # Handle gzipped data
                        try:
                            iodata = BytesIO(bytes(data))
                            data = gzip.GzipFile(fileobj=iodata).read() 
                        except Exception,e:
                            print('This script doesn\'t support decompress more than one gzip frame!')
                    if int(headers[sid].get('content-length', 0)) == res_fd.tell():
                        res_fd.close()
                        del res_files[sid]
                    charset = headers[sid].get('charset', DEFAULT_CHARSET)
                    udata = data.decode(charset)
                    if resources is None: # Only get the subresources from the 1st page 
                        resources = list(set(get_subresources(udata))) # Discard duplicates
                else: # I won't parse it the resource because of the http code, delete
                    del res_files[sid]
                if resources: # Are there more resources to request?
                    res_next = resources.pop()
                    # Make the request
                    connection.write(get_site_resource(spdy_ctx, host, res_next))
                    # Parse the resource path and save it for later when we have data to save
                    res = os.path.realpath(os.path.normpath(res_next)).lstrip('/')
                    res_files[spdy_ctx._last_stream_id] = (os.path.join(out_dir, res), None)
                else:
                    goaway = True
                    if len(res_files)>0:
                        still_open_sids = res_files.keys()
                        for sid in headers:
                            if headers[sid]['content-length']==-1 and \
                                    sid not in still_open_sids:
                                goaway=False
                                break
            else:
                print ('<<', frame) # DEBUG
            frame = get_frame(spdy_ctx)
            if isinstance(frame, Goaway):
                goaway = True
    # Send the goaway
    connection.write(go_away(spdy_ctx, GOAWAY_OK))
    # Close the files created
    for res_path, res_fd in res_files.values():
        if res_fd:
            res_fd.close()
from spdy.connection import Connection, SERVER

b = b'\x80\x02\x00\x01\x01\x00\x01\x0e\x00\x00\x00\x01\x00\x00\x00\x00\x00\x008\xea\xdf\xa2Q\xb2b\xe0b`\x83\xa4\x17\x06{\xb8\x0bu0,\xd6\xae@\x17\xcd\xcd\xb1.\xb45\xd0\xb3\xd4\xd1\xd2\xd7\x02\xb3,\x18\xf8Ps,\x83\x9cg\xb0?\xd4=:`\x07\x81\xd5\x99\xeb@\xd4\x1b3\xf0\xa3\xe5i\x06A\x90\x8bu\xa0N\xd6)NI\xce\x80\xab\x81%\x03\x06\xbe\xd4<\xdd\xd0`\x9d\xd4<\xa8\xa5,\xa0<\xce\xc0\x07J\x089 \xa6\x95\xa5\xa9\xa5%\x03[.\xb0l\xc9Oa`vw\ra`+\x06&\xc7\xdcT\x06\xd6\x8c\x92\x92\x82b\x06f\x90\xbf\x19\xf5\x19\xb8\x10\x99\x95\x01\x18\xf5U\x9999\x89\xfa\xa6z\x06\n\x1a\x11\x00\x19\x1aZ+\xf8d\xe6\x95V(d\x9aY\x98i*8\x02}\x9e\x1a\x9e\x9a\xe4\x9dY\xa2ojl\xaagh\xa8\xa0\xe1\xed\x11\xe2\xeb\xa3\xa3\x90\x93\x99\x9d\xaa\xe0\x9e\x9a\x9c\x9d\xaf\xa9\xe0\x9c\x01,sR\xf5\r\xcd\xf5\x80\x01cf\xacgn\xa9\x10\x9c\x98\x96X\x94\t\xd5\xc4\xc0\x0e\ry\x06\x0eX\x84\x00\x00\x00\x00\xff\xff\x80\x02\x00\x06\x00\x00\x00\x04\x00\x00\x00\x01'

c = Connection(SERVER)
c.incoming(b)
print(c.get_frame())
print(c.get_frame())
print(c.get_frame())
print(c.get_frame())
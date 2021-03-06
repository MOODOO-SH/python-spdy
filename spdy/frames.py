# coding: utf-8
""" Framing definition for SPDY protocol v2/v3, incomplete & unstable ATM. """
DEFAULT_VERSION = 3
VERSIONS = [2, 3]

# Frame IDs
SYN_STREAM = 1
SYN_REPLY = 2
RST_STREAM = 3
SETTINGS = 4
NOOP = 5  # Not implemented, only SPDY v2
PING = 6
GOAWAY = 7
HEADERS = 8
WINDOW_UPDATE = 9

# SYN_STREAM and RST_STREAM Flags
FLAG_FIN = 0x01
FLAG_UNID = 0x02

# RST_STREAM Status Codes
PROTOCOL_ERROR = 1
INVALID_STREAM = 2
REFUSED_STREAM = 3
UNSUPPORTED_VERSION = 4
CANCEL = 5
INTERNAL_ERROR = 6
FLOW_CONTROL_ERROR = 7
STREAM_IN_USE = 8
STREAM_ALREADY_CLOSED = 9
INVALID_CREDENTIALS = 10
FRAME_TOO_LARGE = 11

# SETTINGS Flags
CLEAR_SETTINGS = 0x01

# SETTINGS ID Values
UPLOAD_BANDWIDTH = 1
DOWNLOAD_BANDWIDTH = 2
ROUND_TRIP_TIME = 3
MAX_CONCURRENT_STREAMS = 4
CURRENT_CWND = 5
DOWNLOAD_RETRANS_RATE = 6
INITIAL_WINDOW_SIZE = 7
CLIENT_CERTIFICATE_VECTOR_SIZE = 8

# SETTINGS ID Flags
PERSIST_NONE = 0
PERSIST_VALUE = 1
PERSISTED = 2

# GOAWAY Status Codes
GOAWAY_OK = 0
GOAWAY_PROTOCOL_ERROR = 1
GOAWAY_INTERNAL_ERROR = 11

# Dicts for Debug printing
ERROR_CODES = {
    1: 'PROTOCOL_ERROR',
    2: 'INVALID_STREAM',
    3: 'REFUSED_STREAM',
    4: 'UNSUPPORTED_VERSION',
    5: 'CANCEL',
    6: 'INTERNAL_ERROR',
    7: 'FLOW_CONTROL_ERROR',
}

SETTINGS_ID_VALUES = {
    1: 'UPLOAD_BANDWIDTH',
    2: 'DOWNLOAD_BANDWIDTH',
    3: 'ROUND_TRIP_TIME',
    4: 'MAX_CONCURRENT_STREAMS',
    5: 'CURRENT_CWND',
    6: 'DOWNLOAD_RETRANS_RATE',
    7: 'INITIAL_WINDOW_SIZE',
    8: 'CLIENT_CERTIFICATE_VECTOR_SIZE',
}

SETTINGS_ID_FLAGS = {
    0: 'FLAG_PERSIST_NONE',
    1: 'FLAG_PERSIST_VALUE',
    2: 'FLAG_PERSISTED',
}

GOAWAY_STATUS = {
    0 : 'OK',
    1 : 'PROTOCOL_ERROR',
    11: 'INTERNAL_ERROR',
}

class InvalidFrameError(Exception):
    pass

#definition format
#definition = [
#   (attr or value, num_bits)
#    ...
#]
# false for attr means ignore, string means that attribute, int means value
# -1 for num_bits means 'until the end'

#for isinstance(f, Frame) =)
class Frame(object):
    pass

class DataFrame(Frame):
    """
    +----------------------------------+
    |C|      Stream-ID (31 bits)       |
    +----------------------------------+
    | Flags (8) |    Length (24 bits)  |
    +----------------------------------+
    | Data                             |
    +----------------------------------+
    """

    def __init__(self, stream_id, data, flags=FLAG_FIN):
        self.is_control = False
        self.stream_id = stream_id
        self.data = data
        self.flags = flags
        self.fin = (flags & FLAG_FIN == FLAG_FIN)

    def __repr__(self):
        return 'DATA ({0}) id={1}'.format(len(self.data), self.stream_id)

class ControlFrame(Frame):
    """
    +----------------------------------+
    |C| Version(15bits) | Type(16bits) |
    +----------------------------------+
    | Flags (8) |    Length (24 bits)  |
    +----------------------------------+
    | Data                             |
    +----------------------------------+
    """

    def __init__(self, frame_type, flags=0, version=DEFAULT_VERSION):
        self.is_control = True
        self.frame_type = frame_type
        self.flags = flags
        self.version = version

    def __repr__(self):
        return '? CTRL'

    @classmethod
    def definition(cls, version=DEFAULT_VERSION):
        return cls._definition

class SynStream(ControlFrame):
    """
    +----------------------------------+
    |1|   version = 2  |      1        |
    +----------------------------------+
    | Flags (8) |     Length (24 bits) |
    +----------------------------------+
    |X|     Stream-ID (31bits)         |
    +----------------------------------+
    |X|Associated-To-Stream-ID (31bits)|
    +----------------------------------+
    | Pri (2b)| Unused |               |
    +-------------------               |
    |      Name/value header block     |
    |               ...                |
   +------------------------------------+
   | Number of Name/Value pairs (int16) |
   +------------------------------------+
   |     Length of name (int16)         |
   +------------------------------------+
   |           Name (string)            |
   +------------------------------------+
   |     Length of value  (int16)       |
   +------------------------------------+
   |          Value   (string)          |
   +------------------------------------+
   |           (repeats)                |

    +----------------------------------+
    |1|   version = 3  |      1        |
    +----------------------------------+
    | Flags (8) |     Length (24 bits) |
    +----------------------------------+
    |X|     Stream-ID (31bits)         |
    +----------------------------------+
    |X|Associated-To-Stream-ID (31bits)|
    +----------------------------------+
    | Pri (3b) |Unused |Slot |         |
    +-------------------------        |
    |      Name/value header block     |
    |               ...                |
   +------------------------------------+
   | Number of Name/Value pairs (int32) |
   +------------------------------------+
   |     Length of name (int32)         |
   +------------------------------------+
   |           Name (string)            |
   +------------------------------------+
   |     Length of value  (int32)       |
   +------------------------------------+
   |          Value   (string)          |
   +------------------------------------+
   |           (repeats)                |
    """

    @staticmethod
    def definition(version=DEFAULT_VERSION):
        if version == 2:
            return [
                (False, 1), ('stream_id', 31),
                (False, 1), ('assoc_stream_id', 31),
                ('priority', 2), (False, 14),
                ('headers', -1)
            ]
        else:
            return [
                (False, 1), ('stream_id', 31),
                (False, 1), ('assoc_stream_id', 31),
                ('priority', 3), (False, 5), ('slot', 8),
                ('headers', -1)
            ]

    def __init__(self, stream_id, headers, priority=0, assoc_stream_id=0, \
                 slot=0, flags=FLAG_FIN, version=DEFAULT_VERSION):
        super(SynStream, self).__init__(SYN_STREAM, flags, version)
        self.stream_id = stream_id
        self.assoc_stream_id = assoc_stream_id
        self.headers = headers
        self.priority = priority
        self.slot = slot
        self.fin = (flags & FLAG_FIN == FLAG_FIN)
        self.unidirectional = (flags & FLAG_UNID == FLAG_UNID)

    def __repr__(self):
        return 'SYN_STREAM v{0} id={1}'.format(self.version, self.stream_id)

class SynReply(ControlFrame):
    """
    +----------------------------------+
    |1|   version = 2  |      2        |
    +----------------------------------+
    | Flags (8) |     Length (24 bits) |
    +----------------------------------+
    |X|     Stream-ID (31bits)         |
    +----------------------------------+
    |     Unused       |               |
    +-------------------               |
    |      Name/value header block     |
    |               ...                |
    +----------------------------------+
    
    +----------------------------------+
    |1|   version = 3  |      2        |
    +----------------------------------+
    | Flags (8) |     Length (24 bits) |
    +----------------------------------+
    |X|     Stream-ID (31bits)         |
    +----------------------------------+
    |      Name/value header block     |
    |               ...                |
    +----------------------------------+
    """

    @staticmethod
    def definition(version=DEFAULT_VERSION):
        if version == 2:
            return [
                    (False, 1), ('stream_id', 31),
                    (False, 16),
                    ('headers', -1)
            ]
        else:
            return [
                    (False, 1), ('stream_id', 31),
                    ('headers', -1)
            ]

    def __init__(self, stream_id, headers, flags=0, version=DEFAULT_VERSION):
        super(SynReply, self).__init__(SYN_REPLY, flags, version)
        self.stream_id = stream_id
        self.headers = headers
        self.fin = (flags & FLAG_FIN == FLAG_FIN)

    def __repr__(self):
        return 'SYN_REPLY v{0} id={1}'.format(self.version, self.stream_id)

class RstStream(ControlFrame):
    """
    +----------------------------------+
    |1|   version = 2  |      3        |
    +----------------------------------+
    | Flags (8) | Length (24 bits) = 8 |
    +----------------------------------+
    |X|     Stream-ID (31bits)         |
    +----------------------------------+
    |         Status code              |
    +----------------------------------+
    """

    _definition = [
        (False, 1), ('stream_id', 31),
        ('error_code', 32)
    ]

    def __init__(self, stream_id, error_code, flags=0, version=DEFAULT_VERSION):
        super(RstStream, self).__init__(RST_STREAM, 0, version)
        self.stream_id = stream_id
        self.error_code = error_code

    def __repr__(self):
        return 'RST_STREAM v{0} error={1}'.format(self.version, 
                                                  ERROR_CODES[self.error_code])

class Settings(ControlFrame):
    """
    +----------------------------------+
    |1|      version   |      4        |
    +----------------------------------+
    | Flags (8) |     Length (24 bits) |
    +----------------------------------+
    |        Number of entries         |
    +----------------------------------+
    |    ...  ID/Value Pairs  ...      |
    +----------------------------------+
    
    SPDY v2 ID/Value Pairs:
    +----------------------------------+
    |     ID (24 bits)  | ID_Flags (8) |
    +----------------------------------+
    |         Value (32 bits)          |
    +----------------------------------+
    
    SPDY v3 ID/Value Pairs:    
    +----------------------------------+
    | Flags(8) |      ID (24 bits)     |
    +----------------------------------+
    |          Value (32 bits)         |
    +----------------------------------+
    
    """

    _definition = [
        ('number_of_entries', 32),
        ('id_value_pairs', -1)
    ]

    def __init__(self, number_of_entries, id_value_pairs, flags=0, version=DEFAULT_VERSION):
        super(Settings, self).__init__(SETTINGS, flags, version)
        self.clear_persisted = (flags & CLEAR_SETTINGS == CLEAR_SETTINGS)
        self.number_of_entries = number_of_entries
        self.id_value_pairs = id_value_pairs

    def __repr__(self):
        out = ''
        for id, (id_flag, value) in self.id_value_pairs.items():
            out += '%s=%i,%s' % (SETTINGS_ID_VALUES[id], value,
                                 SETTINGS_ID_FLAGS[id_flag])
        return 'SETTINGS v%s=%s' % (self.version, out[:-2])

class Ping(ControlFrame):
    """
    +----------------------------------+
    |1|      version   |      6        |
    +----------------------------------+
    | Flags(8) = 0 | Length (24 b) = 4 |
    +----------------------------------+
    |                ID                |
    +----------------------------------+
    """

    _definition = [
        ('uniq_id', 32)
    ]

    def __init__(self, uniq_id, flags=0, version=DEFAULT_VERSION):
        super(Ping, self).__init__(PING, 0, version)
        self.uniq_id = uniq_id

    def __repr__(self):
        return 'PING v{0} id={1}'.format(self.version, self.uniq_id)

class Goaway(ControlFrame):
    """
    +----------------------------------+
    |1|  version = 2   |      7        |
    +----------------------------------+
    | Flags (8) |     Length (24 bits) |
    +----------------------------------+
    |X|  Last-good-stream-ID (31 bits) |
    +----------------------------------+
    +----------------------------------+
    |1|  version = 3   |      7        |
    +----------------------------------+
    | Flags(8) = 0 | Length (24 b) = 8 |
    +----------------------------------+
    |X|  Last-good-stream-ID (31 bits) |
    +----------------------------------+
    |           Status Code            |
    +----------------------------------+
    """

    @staticmethod
    def definition(version=DEFAULT_VERSION):
        if version == 2:
            return [
                    (False, 1), ('last_stream_id', 31),
            ]
        else:
            return [
                    (False, 1), ('last_stream_id', 31),
                    ('status_code', 32),
            ]

    def __init__(self, last_stream_id, status_code=None, flags=0, version=DEFAULT_VERSION):
        super(Goaway, self).__init__(GOAWAY, 0, version)
        self.last_stream_id = last_stream_id
        self.status_code = status_code

    def __repr__(self):
        status = GOAWAY_STATUS.get(self.status_code, '')
        return 'GOAWAY v{0} {1}'.format(self.version, status)

class Headers(ControlFrame):
    """
    +----------------------------------+
    |1|   version = 2  |      8        |
    +----------------------------------+
    | Flags (8) |     Length (24 bits) |
    +----------------------------------+
    |X|     Stream-ID (31bits)         |
    +----------------------------------+
    |      Unused     |                |
    +------------------                |
    |      Name/value header block     |
    |               ...                |
    +----------------------------------+
    +----------------------------------+
    |1|   version = 3  |      8        |
    +----------------------------------+
    | Flags (8) |     Length (24 bits) |
    +----------------------------------+
    |X|     Stream-ID (31bits)         |
    +----------------------------------+
    |      Name/value header block     |
    |               ...                |
    +----------------------------------+
    """

    @staticmethod
    def definition(version=DEFAULT_VERSION):
        if version == 2:
            return [
                    (False, 1), ('stream_id', 31),
                    (False, 16),
                    ('headers', -1)
            ]
        else:
            return [
                    (False, 1), ('stream_id', 31),
                    ('headers', -1)
            ]


    def __init__(self, stream_id, headers, flags=0, version=DEFAULT_VERSION):
        super(Headers, self).__init__(HEADERS, 0, version)
        self.stream_id = stream_id
        self.headers = headers

    def __repr__(self):
        return 'HEADERS v{0} id={1}={2}'.format(self.version, self.stream_id,
                                                str(self.headers))

class WindowUpdate(ControlFrame):
    """
    +----------------------------------+
    |1|   version = 3 |        9       |
    +----------------------------------+
    | 0 (flags) |     8 (length)       |
    +----------------------------------+
    |X|     Stream-ID (31-bits)        |
    +----------------------------------+
    |X|  Delta-Window-Size (31-bits)   |
    +----------------------------------+
    """

    _definition = [
        (False, 1), ('stream_id', 31),
        (False, 1), ('delta_window_size', 31)
    ]

    def __init__(self, stream_id, delta_window_size, flags=0, version=DEFAULT_VERSION):
        if version < 3:
            raise InvalidFrameError("WINDOW_UPDATE only exists in spdy/3 and greater")

        super(WindowUpdate, self).__init__(WINDOW_UPDATE, 0, version)
        self.stream_id = stream_id
        self.delta_window_size = delta_window_size

FRAME_TYPES = {
    SYN_STREAM: SynStream,
    SYN_REPLY: SynReply,
    RST_STREAM: RstStream,
    SETTINGS: Settings,
#    NOOP: Noop,
    PING: Ping,
    GOAWAY: Goaway,
    HEADERS: Headers,
    WINDOW_UPDATE: WindowUpdate
}

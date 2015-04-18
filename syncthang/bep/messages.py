# -*- coding: utf-8 -*-

import base64
import datetime
import hashlib
import logging
import struct
import xdrlib

import lz4
import six

from . import baluhn


LOG = logging.getLogger(__name__)

CLUSTER_CONFIG = 0
INDEX = 1
REQUEST = 2
RESPONSE = 3
PING = 4
PONG = 5
INDEX_UPDATE = 6
CLOSE = 7

COMPRESSION_THREASHOLD = 128

_HEADER = struct.Struct('!II')
_SHORT = struct.Struct('!I')

_MESSAGE_TYPES = {}


_b32alphabet = base64._b32tab
if not _b32alphabet:
    _b32alphabet = base64._b32alphabet

_b32_encoder = lambda i: _b32alphabet[i]
_b32_decoder = lambda s: _b32alphabet.index(s)


# NOTE(jkoelker) The Syncthing Protocol uses an incorrect implementation
#                of Luhn mod N. See
#                https://forum.syncthing.net/t/v0-9-0-new-node-id-format/478/4
def luhnish_sum_mod_base(s, base=10, decoder=baluhn.decimal_decoder):
    digits = list(map(decoder, s))
    return (
        sum(digits[-2::-2]) +
        sum(list(map(lambda d: sum(divmod(2 * d, base)), digits[::-2])))
        ) % base

baluhn.luhn_sum_mod_base = luhnish_sum_mod_base


def format_device_id_from_bytes(device_bytes):
    device_id = base64.b32encode(device_bytes)
    device_id = device_id.rstrip('=')
    chunks = list(map(''.join, zip(*[iter(device_id)]*13)))
    lunify = lambda c: baluhn.generate(c, base=32, encoder=_b32_encoder,
                                       decoder=_b32_decoder)
    chunks = [c + lunify(c) for c in chunks]
    device_id = ''.join(chunks)
    chunks = list(map(''.join, zip(*[iter(device_id)]*7)))
    return '-'.join(chunks)


def device_id_from_cert(cert_bytes):
    sha = hashlib.sha256(cert_bytes).digest()
    return sha[:32]


def register(cls_type):
    def _inner(subcls):
        _MESSAGE_TYPES[cls_type] = subcls
        subcls._MESSAGE_TYPE = cls_type
        return subcls
    return _inner


def pack_options(packer, options):
    packer.pack_array(options.items(),
                      lambda key, value: (packer.pack_string(key),
                                          packer.pack_string(value)))


def unpack_options(unpacker):
    items = unpacker.unpack_array(lambda: (unpacker.unpack_string(),
                                           unpacker.unpack_string()))
    return dict(items)


def msg_ids(next_id=0):
    while True:
        yield next_id
        next_id = (next_id + 1) & 0xfff


class FlagMixin(object):
    def _set_value(self, value, mask):
        if value:
            self.flags = self.flags | mask
        else:
            self.flags = self.flags & mask

    def _get_value(self, mask):
        return self.flags & mask != 0


class Connection(six.Iterator):
    def __init__(self, sock, compress=None):
        self.sock = sock
        self.compress = compress
        self.msg_ids = msg_ids()
        self.last_recv = datetime.datetime.now()
        self.last_send = datetime.datetime.now()

    def __iter__(self):
        return self

    def __next__(self):
        if not self.sock:
            raise StopIteration()

        try:
            msg = self.get_message()

            while msg is None:
                msg = self.get()

            return msg

        except Exception:
            LOG.exception('Error getting message')
            self.sock = None
            raise StopIteration()

    def get(self):
        buf = self.sock.recv(8)
        header, length = _HEADER.unpack_from(buf)

        version = header >> 28 & 0xf
        msg_id = header >> 16 & 0xff
        msg_type = header >> 8 & 0xff
        compression = header & 1 == 1

        if version != 0:
            return None

        subcls = _MESSAGE_TYPES.get(msg_type)

        if not subcls:
            return None

        buf = None
        if length > 0:
            buf = self.sock.recv(length)

            if compression:
                buf = lz4.uncompress(buf)

        self.last_recv = datetime.datetime.now()
        return subcls.unpack(msg_id, buf)

    def send(self, message):
        version = (0 & 0xf) << 28
        msg_id = message.msg_id

        if not msg_id:
            msg_id = next(self.msg_ids)
            message.msg_ig = msg_id

        msg_id = (msg_id & 0xfff) << 16
        msg_type = (message._MESSAGE_TYPE & 0xff) << 8

        compress = False
        compression = 0

        if self.compress:
            compress = True

        elif self.compress is False and message._MESSAGE_TYPE != RESPONSE:
            compress = True

        msg = message.pack()

        if compress and len(msg) >= COMPRESSION_THREASHOLD:
            compression = 1
            msg = lz4.compress(msg)

        header = version + msg_id + msg_type + compression
        data = _HEADER.pack(header, len(msg)) + msg
        self.sock.sendall(data)
        self.last_send = datetime.datetime.now()


class Folder(FlagMixin):
    def __init__(self, ident, devices=None, flags=0, options=None):
        if options is None:
            options = {}

        if devices is None:
            devices = []

        self.ident = ident
        self.devices = devices
        self.flags = flags
        self.options = options

    def __str__(self):
        return self.ident

    @classmethod
    def unpack(cls, unpacker):
        ident = unpacker.unpack_string()
        devices = unpacker.unpack_array(lambda: Device.unpack(unpacker))
        flags = unpacker.unpack_uint()
        options = unpack_options(unpacker)

        return cls(ident, devices, flags, options)

    def pack(self, packer):
        packer.pack_string(self.ident)
        packer.pack_array(self.devices, lambda device: device.pack(packer))
        packer.pack_uint(self.flags)
        pack_options(packer, self.options)


class Device(FlagMixin):
    TRUSTED = 1 << 0
    READ_ONLY = 1 << 1
    INTRODUCER = 1 << 2
    SHARE_BITS = 0x000000ff

    def __init__(self, ident, max_local_version=0, flags=0, options=None):
        if options is None:
            options = {}

        self.ident = ident
        self.max_local_version = max_local_version
        self.flags = flags
        self.options = options

    def __str__(self):
        return format_device_id_from_bytes(self.ident)

    @property
    def short(self):
        (short_ident, ) = _SHORT.unpack_from(buffer(self.ident))
        return short_ident

    @classmethod
    def unpack(cls, unpacker):
        ident = unpacker.unpack_opaque()
        max_local_version = unpacker.unpack_uhyper()
        flags = unpacker.unpack_uint()
        options = unpack_options(unpacker)

        return cls(ident, max_local_version, flags, options)

    def pack(self, packer):
        packer.pack_opaque(self.ident)
        packer.pack_uhyper(self.max_local_version)
        packer.pack_uint(self.flags)
        pack_options(packer, self.options)

    @property
    def trusted(self):
        return self._get_value(self.TRUSTED)

    @trusted.setter
    def trusted(self, value):
        self._set_value(self.TRUSTED)

    @property
    def read_only(self):
        return self._get_value(self.READ_ONLY)

    @read_only.setter
    def read_only(self, value):
        self._set_value(self.READ_ONLY)

    @property
    def introducer(self):
        return self._get_value(self.INTRODUCER)

    @introducer.setter
    def introducer(self, value):
        self._set_value(self.INTRODUCER)


@register(CLUSTER_CONFIG)
class ClusterConfig(object):
    def __init__(self, name, version, folders=None, options=None, msg_id=None):
        if options is None:
            options = {}

        if folders is None:
            folders = []

        self.msg_id = msg_id
        self.name = name
        self.version = version
        self.folders = folders
        self.options = options

    @classmethod
    def unpack(cls, msg_id, buf):
        unpacker = xdrlib.Unpacker(buf)

        name = unpacker.unpack_string()
        version = unpacker.unpack_string()
        folders = unpacker.unpack_array(lambda: Folder.unpack(unpacker))
        options = unpack_options(unpacker)

        return cls(name, version, folders, options, msg_id)

    def pack(self):
        packer = xdrlib.Packer()

        packer.pack_string(self.name)
        packer.pack_string(self.version)
        packer.pack_array(self.folders, lambda folder: folder.pack(packer))
        pack_options(packer, self.options)

        return packer.get_buffer()


class FileInfo(FlagMixin):
    DELETED = 1 << 12
    INVALID = 1 << 13
    DIRECTORY = 1 << 14
    NO_PERMISSIONS = 1 << 15
    SYMLINK = 1 << 16
    SYMLING_MISSING_TARGET = 1 << 17
    ALL = (1 << 18) - 1
    SYMLINK_TYPE_MASK = DIRECTORY | SYMLING_MISSING_TARGET

    def __init__(self, name, flags, modified, version, local_version=0,
                 blocks=None):
        if blocks is None:
            blocks = []

        self.name = name
        self.flags = flags
        self.modified = modified
        self.version = version
        self.local_version = local_version
        self.blocks = blocks

    def __str__(self):
        return self.name

    @classmethod
    def unpack(cls, unpacker):
        name = unpacker.unpack_string()
        flags = unpacker.unpack_uint()
        modified = unpacker.unpack_uhyper()
        version = Vector.unpack(unpacker)
        local_version = unpacker.unpack_uhyper()
        blocks = unpacker.unpack_array(lambda: BlockInfo.unpack(unpacker))

        return cls(name, flags, modified, version, local_version, blocks)

    def pack(self, packer):
        packer.pack_string(self.name)
        packer.pack_uint(self.flags)
        packer.pack_uhyper(self.modified)
        Vector(self.version).pack(packer)
        packer.pack_uhyper(self.local_version)
        packer.pack_array(self.blocks, lambda block: block.pack(packer))

    def add_block(self, size, sha):
        self.blocks.append(BlockInfo(size, sha))

    @property
    def deleted(self):
        return self._get_value(self.DELETED)

    @deleted.setter
    def deleted(self, value):
        self._set_value(self.DELETED)

    @property
    def invalid(self):
        return self._get_value(self.INVALID)

    @invalid.setter
    def invalid(self, value):
        self._set_value(self.INVALID)

    @property
    def directory(self):
        return self._get_value(self.DIRECTORY)

    @directory.setter
    def directory(self, value):
        self._set_value(self.DIRECTORY)

    @property
    def no_permissions(self):
        return self._get_value(self.NO_PERMISSIONS)

    @no_permissions.setter
    def no_permissions(self, value):
        self._set_value(self.NO_PERMISSIONS)

    @property
    def symlink(self):
        return self._get_value(self.SYMLINK)

    @symlink.setter
    def symlink(self, value):
        self._set_value(self.SYMLINK)

    @property
    def symlink_missing_target(self, value):
        return self._get_value(self.SYMLINK_MISSING_TARGET)

    @symlink_missing_target.setter
    def symlink_missing_target(self, value):
        self._set_value(self.SYMLINK_MISSING_TARGET)

    @property
    def mode(self):
        return self.flags & 0777

    @mode.setter
    def mode(self, value):
        self.flags = self.flags | (value & 0777)


class Vector(dict):
    @classmethod
    def unpack(cls, unpacker):
        counters = unpacker.unpack_array(lambda: (unpacker.unpack_uhyper(),
                                                  unpacker.unpack_uhyper()))

        return cls(counters)

    def pack(self, packer):
        packer.pack_array(self.items(),
                          lambda ident, value: (packer.pack_uhyper(ident),
                                                packer.pack_uhyper(value)))

    def add(self, ident, value):
        if ident in self and value <= self[ident]:
            return

        self[ident] = value

    def __lt__(self, other):
        for ident in self:
            if ident not in other:
                return False

            if self[ident] > other[ident]:
                return False

        return True

    def __le__(self, other):
        return self == other or self < other

    def __gt__(self, other):
        return other < self

    def __ge__(self, other):
        return self == other or self > other


class BlockInfo(object):
    def __init__(self, size, sha):
        self.size = size
        self.sha = sha

    @classmethod
    def unpack(cls, unpacker):
        size = unpacker.unpack_uint()
        sha = unpacker.unpack_opaque()

        return cls(size, sha)

    def pack(self, packer):
        packer.pack_uint(self.size)
        packer.pack_opaque(self.sha)


@register(INDEX)
class Index(FlagMixin):
    def __init__(self, folder, files, flags=0, options=None, msg_id=None):
        if options is None:
            options = {}

        self.msg_id = msg_id
        self.folder = folder
        self.files = files
        self.flags = flags
        self.options = options

    @classmethod
    def unpack(cls, msg_id, buf):
        unpacker = xdrlib.Unpacker(buf)

        folder = unpacker.unpack_string()
        files = unpacker.unpack_array(lambda: FileInfo.unpack(unpacker))
        flags = unpacker.unpack_uint()
        options = unpack_options(unpacker)

        return cls(folder, files, flags, options, msg_id)

    def pack(self):
        packer = xdrlib.Packer()

        packer.pack_string(self.folder)
        packer.pack_array(self.files, lambda fileinfo: fileinfo.pack(packer))
        packer.pack_uint(self.flags)
        pack_options(packer, self.options)

        return packer.get_buffer()


@register(INDEX_UPDATE)
class IndexUpdate(Index):
    pass


@register(REQUEST)
class Request(FlagMixin):
    def __init__(self, folder, name, offset, size, sha=None, flags=0,
                 options=None, msg_id=None):
        if options is None:
            options = {}

        if sha is None:
            sha = ''

        self.msg_id = msg_id
        self.folder = folder
        self.name = name
        self.offset = offset
        self.size = size
        self.sha = sha
        self.flags = flags

    @classmethod
    def unpack(cls, msg_id, buf):
        unpacker = xdrlib.Unpacker(buf)

        folder = unpacker.unpack_string()
        name = unpacker.unpack_string()
        offset = unpacker.unpack_uhyper()
        size = unpacker.unpack_uint()
        sha = unpacker.unpack_opaque()
        flags = unpacker.unpack_uint()
        options = unpack_options(unpacker)

        return cls(folder, name, offset, size, sha, flags, options, msg_id)

    def pack(self):
        packer = xdrlib.Packer()

        packer.pack_string(self.folder)
        packer.pack_string(self.name)
        packer.pack_uhyper(self.offset)
        packer.pack_uint(self.size)
        packer.pack_opaque(self.sha)
        packer.pack_uint(self.flags)
        pack_options(packer, self.options)

        return packer.get_buffer()


@register(RESPONSE)
class Response(object):
    NO_ERROR = 0
    ERROR = 1
    NO_SUCH_FILE = 2
    INVALID = 3

    def __init__(self, data, code, msg_id=None):
        self.msg_id = msg_id
        self.data = data
        self.code = code

    @classmethod
    def unpack(cls, msg_id, buf):
        unpacker = xdrlib.Unpacker(buf)

        data = unpacker.unpack_opaque()
        code = unpacker.unpack_uint()

        return cls(data, code, msg_id)

    def pack(self):
        packer = xdrlib.Packer()

        packer.pack_opaque(self.data)
        packer.pack_uint(self.code)

        return packer.get_buffer()


class PingPong(object):
    def __init__(self, msg_id=None):
        self.msg_id = msg_id

    @classmethod
    def unpack(cls, msg_id, buf):
        return cls(msg_id)

    def pack(self):
        return ''


@register(PING)
class Ping(PingPong):
    pass


class Pong(PingPong):
    pass


@register(CLOSE)
class Close(object):
    def __init__(self, reason, code, msg_id=None):
        self.msg_id = msg_id
        self.reason = reason
        self.code = code

    @classmethod
    def unpack(cls, msg_id, buf):
        unpacker = xdrlib.Unpacker(buf)

        reason = unpacker.unpack_string()
        code = unpacker.unpack_uint()

        return cls(reason, code, msg_id)

    def pack(self):
        packer = xdrlib.Packer()

        packer.pack_string(self.reason)
        packer.pack_uint(self.code)

        return packer.get_buffer()

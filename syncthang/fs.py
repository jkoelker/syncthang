# -*- coding: utf-8 -*-

import hashlib
import os

from eventlet import tpool
import walkdir

from .bep import protocol
from .bep import messages


NOTHING_SHA = hashlib.sha256().digest()


def _hash_file(stream):
    blocks = []
    add_block = blocks.append

    offset = 0
    data = stream.read(protocol.BLOCK_SIZE)

    while data:
        sha = hashlib.sha256(data).digest()
        size = len(data)
        add_block(messages.BlockInfo(sha, size, offset))

        offset = offset + size
        data = stream.read(protocol.BLOCK_SIZE)

    if not blocks:
        add_block(messages.BlockInfo(NOTHING_SHA, 0, 0))

    return blocks


def hash_file(file_path):
    with open(file_path, mode='rb') as stream:
        return _hash_file(stream)


class Walker(object):
    def __init__(self, path):
        self.path = path

    def walk(self):
        walk_iter = walkdir.filtered_walk(self.path)
        for dirpath, subdirs, files in walk_iter:
            for fname in files:
                real_path = os.path.abspath(os.path.join(dirpath, fname))

                if os.path.islink(real_path):
                    target = os.readlink(real_path)

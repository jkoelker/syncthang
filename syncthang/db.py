# -*- coding: utf-8 -*-

import logging

import sqlalchemy as sa
from sqlalchemy.ext import declarative

from .bep import messages


LOG = logging.getLogger(__name__)


class _Base(object):
    _id = sa.Column('_id', sa.Integer, primary_key=True)

    @declarative.declared_attr
    def __tablename__(cls):
        # NOTE(jkoelker) use the pluralized name of the class as the table
        return cls.__name__.lower() + 's'

Base = declarative.declarative_base(cls=_Base)


class BlockInfo(Base, messages.BlockInfo):
    size = sa.Column(sa.BigInteger)
    sha = sa.Column(sa.String)

    @classmethod
    def from_message(cls, msg):
        return cls(size=msg.size, sha=msg.sha)


class FileInfo(Base, messages.FileInfo):
    name = sa.Column(sa.String)
    flags = sa.Column(sa.Integer)
    modified = sa.Column(sa.BigInteger)
    version = kv.KeyStore(peewee.CharField())
    local_version = sa.Column(sa.BigInteger)
    blocks = shortcuts.ManyToManyField(BlockInfo, related_name='files')


class Device(messages.Device, Base):
    ident = peewee.CharField(max_length=32)
    max_local_version = peewee.BigIntegerField()
    flags = peewee.IntegerField()
    options = kv.KeyStore(peewee.CharField())

    name = peewee.CharField()
    version = peewee.CharField()

    def __init__(self, *args, **kwargs):
        Base.__init__(self, *args, **kwargs)

    @classmethod
    def from_message(cls, msg):
        return cls(ident=msg.ident, devices=msg.devices, flags=msg.flags,
                   options=msg.options)


class Folder(messages.Folder, Base):
    ident = peewee.CharField(max_length=64)
    devices = shortcuts.ManyToManyField(Device, related_name='folders')
    flags = peewee.IntegerField()
    options = kv.KeyStore(peewee.CharField())

    def __init__(self, *args, **kwargs):
        Base.__init__(self, *args, **kwargs)

    @classmethod
    def from_message(cls, msg):
        devices = [Device.from_message(d) for d in msg.devices]
        return cls(ident=msg.ident, devices=devices, flags=msg.flags,
                   options=msg.options)

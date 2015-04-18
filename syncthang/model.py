# -*- coding: utf-8 -*-

import collections
import weakref

from eventlet import event

from .bep import messages
from . import db


class Model(object):
    def __init__(self, client_name, client_version):
        self.client_name = client_name
        self.client_versin = client_version

        self.update = event.Event()
        self.devices = weakref.WeakValueDictionary()

        self._folder_devices = collections.defaultdict(list)
        self._device_folders = collections.defaultdict(list)

    def cluster_config(self, device_id):
        folders = db.Device.select(db.Device.folders)
        folders = folders.where(db.Device.ident == device_id)
        msg = messages.ClusterConfig(self.client_name,
                                     self.client_version,
                                     folders)
        return msg

    def update_cluster_config(self, device_id, name, version, folders,
                              options):
        device = db.Device.get(db.Device.ident == device_id)
        device.name = name
        device.version = version
        device.save()

        if device.introducer:
            # TODO(jkoelker) create new connections to devices
            pass

    def folder_index(self, folder, min_local_version):
        pass

    def update_index(self, index):
        pass

    def request(folder, name, offset, size, sha, flags):
        pass

    def index_update(self, device_id, folder, files, flags, options):
        pass

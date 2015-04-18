# -*- coding: utf-8 -*-

import datetime
import logging

import eventlet

from . import messages


LOG = logging.getLogger(__name__)
PING_IDLE_TIME = datetime.timedelta(seconds=60)
BLOCK_SIZE = 128 * 1024


class RemoteDevice(object):
    def __init__(self, device_id, sock, model, compress=None,
                 response_handler=None):
        self.device_id = device_id
        self.sock = sock
        self.model = model
        self.response_handler = response_handler

        self.name = None
        self.version = None

        self.conn = messages.Messages(sock, compress)

        self._health_interval = PING_IDLE_TIME.total_seconds() / 2
        self._health_timer = eventlet.spawn_after(self._health_interval,
                                                  self.healthcheck)

    def send(self, msg):
        self.conn.send(msg)

    def start(self):
        self._health_timer.start()
        self.send(self.model.cluster_config(self.device_id))

        def _wait_for_update():
            self.model.update.wait()
            self.send_index_update()
            eventlet.spawn(_wait_for_update)

        eventlet.spawn(_wait_for_update)

        for msg in self.conn:
            handler = None

            if msg._MESSAGE_TYPE == messages.CLUSTER_CONFIG:
                handler = self.cluster_config

            elif msg._MESSAGE_TYPE == messages.INDEX:
                handler = self.index

            elif msg._MESSAGE_TYPE == messages.REQUEST:
                handler = self.request

            elif msg._MESSAGE_TYPE == messages.RESPONSE:
                handler = self.response

            elif msg._MESSAGE_TYPE == messages.PING:
                handler = self.ping

            elif msg._MESSAGE_TYPE == messages.PONG:
                handler = self.pong

            elif msg._MESSAGE_TYPE == messages.INDEX_UPDATE:
                handler = self.index_update

            elif msg._MESSAGE_TYPE == messages.CLOSE:
                handler = self.close

            if handler is not None:
                handler(msg)

    def stop(self):
        self._health_timer.cancel()
        self.sock.close()

    def healthcheck(self):
        recv = datetime.datetime.now() - self.conn.last_recv
        send = datetime.datetime.now() - self.conn.last_send

        if recv < PING_IDLE_TIME or send < PING_IDLE_TIME:
            return

        self.send(messages.Ping())
        self._health_timer = eventlet.spawn_after(self._health_interval,
                                                  self.healthcheck)

    def send_index_update(self):
        pass

    def send_request(self, folder, name, offset, size, sha=None, flags=0,
                     options=None):
        msg = messages.Request(folder, name, offset, size, sha, flags,
                               options)
        self.send(msg)
        return msg.msg_id

    def close(self, msg):
        LOG.info('Connection to %s closed: %s', self.name, msg.reason)
        self.stop()

    def cluster_config(self, msg):
        if self.name or self.version:
            LOG.error('Additional cluster config recieved from %s', self.name)
            return self.stop()

        self.name = msg.name
        self.version = msg.version

        self.model.update_cluster_config(self.device_id, self.name,
                                         self.version, msg.folders,
                                         msg.options)

    def index(self, msg):
        self.model.update_index(self.device_id, msg.folder, msg.files,
                                msg.flags, msg.options)

    def index_update(self, msg):
        return self.index(msg)

    def ping(self, msg):
        LOG.debug('Device: %s ping requested', self.name)
        self.send(messages.Pong(msg_id=msg.msg_id))

    def pong(self, msg):
        LOG.debug('Device: %s pong revieved', self.name)

    def request(self, msg):
        LOG.debug('Request from %s code: %s', self.name, msg.code)
        code = messages.Response.NO_ERROR

        try:
            data = self.model.request(msg.folder, msg.name, msg.offset,
                                      msg.size, msg.sha, msg.flags)

        except Exception:
            code = messages.Response.ERROR

        self.send(messages.Reponse(data, code, msg_id=msg.msg_id))

    def response(self, msg):
        LOG.debug('Response from %s code: %s', self.name, msg.code)
        if self.response_handler:
            self.response_handler(msg.msg_id, msg.data, msg.code)

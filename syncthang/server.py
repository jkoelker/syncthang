# -*- coding: utf-8 -*-

import functools
import logging

from eventlet.green.OpenSSL import crypto
import eventlet

from .bep import messages
from .bep import protocol


LOG = logging.getLogger(__name__)


def cert_to_device_id(cert):
    cert_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    return messages.device_id_from_cert(cert_bytes)


def start_remote(local_device_id, model, sock, addr):
    cert = sock.get_peer_certificate()
    device_id = cert_to_device_id(cert)

    if local_device_id == device_id:
        LOG.info('Connected to myself (%s) - should not happen', device_id)
        sock.shutdown()
        sock.close()

    if device_id in model.devices:
        LOG.info('Connected to already connected device (%s)', device_id)
        sock.shutdown()
        sock.close()

    remote_device = protocol.RemoteDevice(device_id, sock, model)
    model.devices[device_id] = remote_device
    remote_device.start()


def serve(sock, device_id, model):
    eventlet.serve(sock, functools.partial(start_remote, device_id, model))

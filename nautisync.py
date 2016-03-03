#!/usr/bin/env python
# -*- coding: utf-8 -*-

# NautiSync - library for exchanging messages between processes / threads via mulicast UDP protocol
#
# Functions:
#   - exchanging messages between threads
#   - exchanging messages between processes
#   - exchanging messages between threads and processes on separate systems over network
#   - authentication of messages by shared secret and hmac algorithm
#   - possibility to select any digest method for hmac
#   - protection against replay attack (each message have unique sequence number)
#   - exchanging data in OneToMany, ManyToOne, ManyToMany schemes
#   - each node offers send and receive function
#   - heart beat system included, nodes are aware about each other
#   - utilization of fastest available serialization module: msgpack (several times faster than cpickle)
#   - can send any variable or object that can be serialized by msgpack
#
# Version 1.2
# Author: Marek Ryn (marek.ryn@nuatisys.pl)
#
# Change log:
#    1.0 - Initial version
#    1.1 - Support for name and group (format: name@group)
#    1.2 - Added support for queues and multi threading applications
#        - Possibility to assign several nodes to one Context (i.e. one for each thread)
#        - Optimization for speed
#        - Code cleanup
#
# TODO:
#   - network adapter selection
#   - method for obtaining list of available nodes by filter

import socket
import struct
import msgpack as packer
import hmac
from threading import Thread
from time import sleep, time
from queue import Queue, Empty, Full


class Node(object):
    """
    Object representing single sender/receiver in NautiSync network.
    """

    def __init__(self, uuid, txqueue, counter=0, owner=True):
        if isinstance(uuid, str):
            uuid = uuid.encode()
        self.owner = owner
        self.counter = counter
        self.last_hb = time()
        self.buffer = None
        self.rxQueue = Queue()
        self.txQueue = txqueue
        self.uuid = uuid
        (self.name, self.group) = uuid.split(b'@')

    def send(self, dest_uuid, data):
        """
        Send data to destanation node
        :param dest_uuid: uuid of destanation node
        :param data: any object that can be serialized by msgpack
        :return: True on success, False on failure
        """
        try:
            assert self.owner
            if isinstance(dest_uuid, str):
                dest_uuid = dest_uuid.encode()
            self.txQueue.put((self.uuid, dest_uuid, data), False)
            return True
        except (Full, AssertionError):
            return False

    def receive(self):
        """
        Returns tuple (sender_uuid, data)
        :return: (sender_uuid, data)
        """
        try:
            assert self.owner
            return self.rxQueue.get(False)
        except (AssertionError, Empty):
            return None

    def delete(self):
        """
        After executing of this method, node will be automatically deleted during next garbage collecting
        WARNING: deletion will be registered on other nodes by not detecting hearbeat sequence.
        """
        self.owner = False
        self.last_hb = 0


class Context(Thread):
    """
    Context for NautiSync network.
    """

    def __init__(self, mcast_group, mcast_port, mcast_secret, hashalg='sha1', packetsize=1024):
        """
        Creates context for NautiSync network.
        :param mcast_group: string representing multicast group ip
        :param mcast_port: int representing multicast port
        :param mcast_secret: string with shared secret
        :param hashalg: string with digest algorithm name (default: 'sha1')
        :param packetsize: size of chunk of data
        """

        Thread.__init__(self)

        if isinstance(mcast_secret, str):
            mcast_secret = mcast_secret.encode()

        self.mcast_group = mcast_group
        self.mcast_port = mcast_port
        self.mcast_secret = mcast_secret
        self.packetsize = packetsize

        self._txqueue = Queue()
        self._hashalg = hashalg
        self._nodes = {}
        self._loopdelay = 0.005  # Main loop delay in seconds, when no messages are received
        self._hbdelay = 5  # Time from last send message after which heartbeat is generated [seconds]
        self._hbdelete = 10  # Time after which node is deleted from memory due to inactivity [seconds]

        # Configuring sending socket
        self.tx_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.tx_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)

        # Configuring receiving socket
        self.rx_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.rx_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rx_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024*512)
        try:
            self.rx_socket.bind((self.mcast_group, self.mcast_port))
        except OSError:
            # For Windows
            self.rx_socket.bind(('', self.mcast_port))
        mreq = struct.pack("4sl", socket.inet_aton(self.mcast_group), socket.INADDR_ANY)
        self.rx_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.rx_socket.setblocking(False)

        # Starting NautiSync daemon
        self.setDaemon(True)
        self.start()

    def getnode(self, uuid):
        """
        Returns Node object assigned to given uuid
        :param uuid: unique id in format name@group
        :return: Node instance
        """
        if isinstance(uuid, str):
            uuid = uuid.encode()
        if uuid not in self._nodes:
            self._nodes[uuid] = Node(uuid, self._txqueue)
        return self._nodes[uuid]

    def delnode(self, uuid):
        """
        Delates node from memory. WARNING: deletion will be registered on other nodes by not detecting
        hearbeat sequence.
        :param uuid: uuid of node selected for deletion
        """
        if self._nodes[uuid].owner:
            del(self._nodes[uuid])

    def getnodeslist(self):
        """
        Returns active nodes' list
        :return: node list
        """
        return self._nodes.keys()

    def _send(self, tx_uuid, rx_uuid, data):
        data = packer.dumps(data, encoding='utf-8', use_bin_type=True)
        i = 0
        s = int(len(data)/self.packetsize)
        while data[i*self.packetsize:i*self.packetsize+self.packetsize]:
            self._nodes[tx_uuid].last_hb = time()
            self._nodes[tx_uuid].counter += 1
            packet = packer.dumps((self._nodes[tx_uuid].counter, i, s, tx_uuid, rx_uuid,
                                   data[i*self.packetsize:i*self.packetsize+self.packetsize]))
            h = hmac.new(self.mcast_secret, packet, self._hashalg)
            packet = h.digest() + packet
            self.tx_socket.sendto(packet, (self.mcast_group, self.mcast_port))
            i += 1

    def run(self):
        while True:
            t = time()
            try:
                # Receiving data
                data = self.rx_socket.recv(self.packetsize*2)
                try:
                    # HMAC check
                    h = hmac.new(self.mcast_secret, msg=None, digestmod=self._hashalg)
                    rh = data[:h.digest_size]
                    data = data[h.digest_size:]
                    h.update(data)
                    assert hmac.compare_digest(h.digest(), rh)

                    # Decoding package
                    (counter, i, s, source_uuid, dest_uuid, data) = packer.loads(data)
                    if source_uuid not in self._nodes:
                        self._nodes[source_uuid] = Node(source_uuid, self._txqueue, owner=False)

                    # Counter check
                    assert (counter > self._nodes[source_uuid].counter)
                    self._nodes[source_uuid].counter = counter
                    self._nodes[source_uuid].last_hb = t

                    # All OK. Process received data.
                    if i == 0:
                        self._nodes[source_uuid].buffer = b''
                    if i <= s:
                        self._nodes[source_uuid].buffer += data
                    if i == s:
                        data = packer.loads(self._nodes[source_uuid].buffer, encoding='utf-8')
                        (dest_name, dest_group) = dest_uuid.split(b'@')
                        for uuid in self._nodes.keys():
                            if uuid == source_uuid:
                                continue
                            if (self._nodes[uuid].name != dest_name) and (dest_name != b'*'):
                                continue
                            if (self._nodes[uuid].group != dest_group) and (dest_group != b'*'):
                                continue
                            if data:
                                self._nodes[uuid].rxQueue.put((source_uuid, data))

                except (AssertionError, ValueError, TypeError):
                    pass

            except (BlockingIOError, OSError):
                # No activity
                if self._txqueue.empty():
                    sleep(self._loopdelay)

                # Heartbeat - proof that node is alive
                for uuid in self._nodes.keys():
                    if ((t - self._nodes[uuid].last_hb) > self._hbdelay) and self._nodes[uuid].owner:
                        self._send(uuid, '*@*', None)

                # Garbage collector - deleting inactive nodes
                for uuid in list(self._nodes.keys()):
                    if ((t-self._nodes[uuid].last_hb) > self._hbdelete) and (not self._nodes[uuid].owner):
                        del(self._nodes[uuid])

            # Sending queued data
            while not self._txqueue.empty():
                (tx_uuid, rx_uuid, data) = self._txqueue.get(False)
                self._send(tx_uuid, rx_uuid, data)

# TEST
if __name__ == '__main__':
    from random import randrange

    ns = Context('224.0.0.1', 5000, 'SECRET PASSWORD')

    ns_uuid = str(randrange(100))+'@Group' + str(randrange(1000))
    node = ns.getnode(ns_uuid)

    while True:
        # ns_data = input(ns_uuid+' >')
        # if ns_data == 'LIST':
        #     print(ns._nodes.keys())
        # else:
        #    node.send('*@*', ns_data)
        while not node.rxQueue.empty():
            print('Received data: ', node.rxQueue.get(False))
        sleep(0.2)

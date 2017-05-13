# -*- coding: utf-8 -*-
## @package multicast_chat.__main__
# Multicast chat with impersonation prevention.
#

import argparse
import logging
import os
import string
import sys
import time
import traceback


import gcap
import gutil


from . import base
from . import packets


## Package name.
PACKAGE_NAME = 'multicast_chat'
## Package version.
PACKAGE_VERSION = '0.0.0'


## Escape key.
CHAR_ESCAPE = chr(27)

## Backspace key.
# Two options for *NIX/Windows.
CHARS_BACKSPACE = ('\b', chr(127))

## Time to wait for packet."""
GCAP_TIMEOUT = 100


## Exit exception.
#
# Thrown when user choses to exit.
#
class ExitException(Exception):
    """Exit exception.

    Thrown when user chooses to exit."""
    pass


## Name repository.
#
# Manages impersonation prevention based on mac address.
#
class NameRepository(base.Base):
    ## Timeout in seconds for house keeping.
    _HOUSE_KEEPING_INTERVAL = 5
    ## Name time to live interval in seconds.
    _NAME_TTL = 60

    ## Last house keeping time.
    _last_housekeeping_time = 0

    ## Get a display name for MAC address.
    # @param name (str) name.
    # @param mac (bytes) MAC address
    # @returns (str) display name
    #
    @staticmethod
    def _get_display_for_name(name, mac):
        return "'%s'@%s" % (
            name,
            packets.EthernetPacket.mac_to_string(mac),
        )

    ## Constructor.
    def __init__(self):
        super(NameRepository, self).__init__()
        self._registration_repo = {}

    ## Register/refresh a name.
    # @arg name (str) name.
    # @arg mac (bytes) MAC address.
    #
    # Will be applied only if mac matches or name is not registered.
    #
    def register_name(
        self,
        name,
        mac,
        should_expire=True,
    ):
        entry = self._registration_repo.get(name)

        do_register = False
        if entry is None:
            do_register = True
        elif entry['mac'] != mac:
            self.logger.warning(
                'Attempt to impersonate to %s by %s',
                self._get_display_for_name(entry['name'], entry['mac']),
                packets.EthernetPacket.mac_to_string(mac),
            )
        else:
            do_register = True

        if do_register:
            if entry is not None and entry['expire'] is None:
                self.logger.debug(
                    'Ignoring attempt to refresh non expired %s',
                    self._get_display_for_name(entry['name'], entry['mac']),
                )
            else:
                if entry is None:
                    self.logger.info(
                        'Registering: %s',
                        self._get_display_for_name(name, mac),
                    )
                else:
                    self.logger.debug(
                        'Refreshing: %s',
                        self._get_display_for_name(name, mac),
                    )

                self._registration_repo[name] = {
                    'name': name,
                    'mac': mac,
                    'expire': (
                        time.time() + self._NAME_TTL if should_expire
                        else None
                    ),
                }

    ## Unregister a name.
    # @param name (string) name.
    # @param mac (bytearray) mac address.
    # Will be applied only if mac matches.
    #
    def unregister_name(
        self,
        name,
        mac,
    ):
        entry = self._registration_repo.get(name)
        if entry is None:
            self.logger.debug(
                'Ignoring unregister %s it is not in database',
                self._get_display_for_name(name, mac),
            )
        elif entry['mac'] != mac:
            self.logger.warning(
                'Trying to unregister %s by %s',
                self._get_display_for_name(entry['name'], entry['mac']),
                packets.EthernetPacket.mac_to_string(mac),
            )
        else:
            self.logger.info(
                'Unregistering %s',
                self._get_display_for_name(entry['name'], entry['mac']),
            )
            del self._registration_repo[name]

    ## Returns True if name can by used by mac.
    #
    # @param name (str) subject.
    # @param mac (bytearray) mac addres.
    # @returns (bool) True if approved.
    #
    def is_name_valid(self, name, mac):
        return self._registration_repo.get(name, {}).get('mac') == mac

    ## Perform housekeeping tasks.
    #
    def housekeeping(self):
        now = time.time()
        if self._last_housekeeping_time < now - self._HOUSE_KEEPING_INTERVAL:
            self._last_housekeeping_time = now

            self.logger.debug('Housekeeping')

            #
            # Remove expired names.
            #
            to_delete = []
            for entry in self._registration_repo.values():
                if entry['expire'] is not None and entry['expire'] < now:
                    self.logger.debug(
                        "Removing expired %s",
                        self._get_display_for_name(
                            entry['name'],
                            entry['mac'],
                        ),
                    )
                    to_delete.append(entry['name'])
            for name in to_delete:
                del self._registration_repo[name]


## Layer abstract base implementation.
# A base class for all layers.
#
class Layer(base.Base):
    ## Operation mode
    (
        MODE_NORMAL,
        MODE_STOPPING,
    ) = range(2)

    ## Operation mode mapping
    MODE_STR = {
        MODE_NORMAL: 'Normal',
        MODE_STOPPING: 'Stopping',
    }

    ## Data element.
    class QueuedData(base.Base):

        ## Constructor.
        # @param protocol (object) protocol selection.
        # @param dst (object) destination address.
        # @param src (object) source address.
        # @param data (bytearray) payload.
        # @param display (str) eye catcher.
        #
        def __init__(
            self,
            protocol=None,
            dst=None,
            src=None,
            data=None,
            display='QueuedData',
        ):
            super(Layer.QueuedData, self).__init__()
            self.protocol = protocol
            self.dst = dst
            self.src = src
            self.data = data
            self.display = display

        ## String representation.
        def __repr__(self):
            return Layer.string_to_printable(self.display)

    ## Operation mode.
    _mode = MODE_NORMAL

    ## Retrive lower layer.
    @property
    def lower_layer(self):
        return self._lower_layer

    ## Retrive address of layer.
    @property
    def address(self):
        return self._address

    ## Retrive operation mode.
    @property
    def mode(self):
        return self._mode

    ## Constructor.
    # @param lower_layer (Layer) lower layer to register into.
    # @param address (optional, object) address of this layer.
    #
    def __init__(
        self,
        lower_layer,
        address=None,
    ):
        super(Layer, self).__init__()
        self._lower_layer = lower_layer
        self._address = address

        self._protocols = set()
        self._send_queue = []
        self._receive_queue = []

        self.logger.debug(
            "Initializing layer '%s' with lower '%s' address '%s'",
            self,
            lower_layer,
            self.address_to_string(address),
        )

    ## String representation.
    def __repr__(self):
        return 'Abstract Layer'

    ## Resolve address to string.
    # @param address (bytes) string representation.
    # @returns (str) string representation.
    #
    @staticmethod
    def address_to_string(address):
        return address

    ## Return printable chars only.
    # @param s (string) printable string.
    #
    @staticmethod
    def string_to_printable(s):
        return ''.join(x for x in s.__repr__() if x in string.printable)

    ## Register protocol within this layer.
    # @param protocol (object) requested protocol.
    #
    # Used to filter out unneeded data, so data won't be queueued
    # if nobody will ever deque them.
    #
    def register_protocol(self, protocol):
        self.logger.debug(
            "Layer '%s' registering protocol '%s'",
            self,
            protocol,
        )
        self._protocols.add(protocol)

    ## Unegister protocol within this layer.
    # @param protocol (object) requested protocol.
    #
    def unregister_protocol(self, protocol):
        self.logger.debug(
            "Layer '%s' unregistering protocol '%s'",
            self,
            protocol,
        )
        self._protocols.remove(protocol)

        # remove all protocol data from queue
        while self.receive(protocol=protocol):
            pass

    ## Change operation mode.
    # @param mode (int) operation mode.
    #
    def change_mode(self, mode):
        self.logger.debug(
            "Layer '%s' change mode '%s'",
            self,
            self.MODE_STR.get(mode, 'Invalid'),
        )
        self._mode = mode

    ## Check if this layer has some work to do.
    # @returns (bool) True if has work.
    #
    def has_work(self):
        return len(self._send_queue) > 0 or len(self._receive_queue) > 0

    ## Send data to this layer.
    # @param queued_data (@ref QueuedData): data to send.
    #
    def send(self, queued_data):
        self.logger.debug(
            "Layer '%s' send '%s'",
            self,
            queued_data.__str__(),
        )
        self._send_queue.append(queued_data)

    ## Receive data from this layer.
    # @param protocol (object) requested protocol.
    # @returns (@ref QueuedData) data or None.
    #
    def receive(self, protocol=None):
        for i in range(len(self._receive_queue)):
            if self._receive_queue[i].protocol == protocol:
                queued_data = self._receive_queue.pop(i)
                self.logger.debug(
                    "Layer '%s' recieve '%s'",
                    self,
                    queued_data,
                )
                return queued_data

    ## Queue data to be recieved by upper layer.
    # @param queued_data (@ref QueuedData) data to queue.
    #
    # Data will be returned to upper layer when it
    # calls recieve().
    #
    def queue_receive(self, queued_data):
        if (
            queued_data.protocol is None or
            queued_data.protocol in self._protocols
        ):
            self.logger.debug(
                "Layer '%s' queue receive '%s'",
                self,
                queued_data,
            )
            self._receive_queue.append(queued_data)

    ## "Dequeue data sent by upper layer.
    #
    # Returns data that was sent to this layer by upper layer
    # using send().
    #
    def dequeue_send(self):
        if self._send_queue:
            queued_data = self._send_queue.pop(0)
            self.logger.debug(
                "Layer '%s' dequeue send '%s'",
                self,
                queued_data.__str__(),
            )
            return queued_data
        else:
            return None

    ## Layer logic.
    def process(self):
        pass


## Physical layer implementation.
#
# Uses gcap to receive/send packets.
#
class PhysicalLayer(Layer):

    ## Constructor.
    # cap (Cap) reference to gcap instance.
    #
    def __init__(
        self,
        cap,
    ):
        super(PhysicalLayer, self).__init__(
            lower_layer=None,
        )
        self._cap = cap

    ## @copydoc Layer#__repr__
    def __repr__(self):
        return 'Pysical Layer'

    ## @copydoc Layer#process
    def process(self):
        super(PhysicalLayer, self).process()

        while True:
            d = self.dequeue_send()
            if d is None:
                break
            self._cap.send_packet(d.data)

        if self.mode == self.MODE_NORMAL:
            cap_packet = self._cap.next_packet()
            if cap_packet:
                self.queue_receive(
                    queued_data=self.QueuedData(
                        data=cap_packet['data'],
                    )
                )


## Ethernet II layer.
#
class EthernetLayer(Layer):

    ## Constructor.
    # @param lower_layer (@ref Layer) lower layer to interact with.
    # @param address (bytearray) local mac address.
    # @param local_loopback_mode (bool) debug only mode process own packets.
    #
    def __init__(
        self,
        lower_layer,
        address,
        local_loopback_mode,
    ):
        super(EthernetLayer, self).__init__(
            lower_layer=lower_layer,
            address=address,
        )
        self._local_loopback_mode = local_loopback_mode

    ## @copydoc Layer#__repr__
    def __repr__(self):
        return 'Ethernet Layer'

    ## Map address to a string.
    # @param address (bytes) address.
    # @returns (str) string representation.
    @staticmethod
    def address_to_string(address):
        return packets.EthernetPacket.mac_to_string(address)

    ## @copydoc Layer#process
    def process(self):
        super(EthernetLayer, self).process()

        while True:
            d = self.lower_layer.receive()
            if d is None:
                break
            packet = packets.EthernetPacket.decode(d.data)
            if self._local_loopback_mode or packet.src != self.address:
                self.queue_receive(
                    queued_data=self.QueuedData(
                        protocol=packet.ethertype,
                        dst=packet.dst,
                        src=packet.src,
                        data=packet.data,
                        display=packet,
                    )
                )

        while True:
            d = self.dequeue_send()
            if d is None:
                break
            packet = packets.EthernetPacket(
                ethertype=d.protocol,
                dst=d.dst,
                src=d.src if d.src else self.address,
                data=d.data,
            )
            self.lower_layer.send(
                self.QueuedData(
                    data=packet.encode(),
                    display=packet,
                )
            )


## Registration layer.
class RegistrationLayer(Layer):

    ## Name announce interval.
    _ANNOUNCE_INTERVAL = 2

    ## Last time announced.
    _last_announce_time = 0

    ## Announce registration status.
    # @param command (int) command to send.
    #
    def _announce(self, command):
        packet = packets.RegistrationPacket(
            command=command,
            name=self._local_name,
        )
        self.lower_layer.send(
            queued_data=self.QueuedData(
                protocol=packets.RegistrationPacket.ETHERTYPE,
                dst=packets.EthernetPacket.MAC_BROADCAST,
                data=packet.encode(),
                display=packet,
            )
        )

    ## Constructor.
    # @param lower_layer (@ref Layer) lower layer to interact with.
    # @param name_repository (@ref NameRepository) name repository
    #   to interact with.
    # @param local_name (str) local name to announce.
    #
    def __init__(
        self,
        lower_layer,
        name_repository,
        local_name,
    ):
        super(RegistrationLayer, self).__init__(
            lower_layer=lower_layer,
        )
        self._local_name = local_name
        self._name_repository = name_repository

        self.lower_layer.register_protocol(
            protocol=packets.RegistrationPacket.ETHERTYPE,
        )

        #
        # Register our own name so nobody can
        # impersonate to us.
        # This entry should not expire.
        #
        self._name_repository.register_name(
            name=self._local_name,
            mac=self.lower_layer.address,
            should_expire=False,
        )

    ## Destructor.
    def __del__(self):
        self._name_repository.unregister_name(
            name=self._local_name,
            mac=self.lower_layer.address,
        )
        self.lower_layer.unregister_protocol(
            protocol=packets.RegistrationPacket.ETHERTYPE,
        )

    ## @copydoc Layer#__repr__
    def __repr__(self):
        return 'Registration Layer'

    ## @copydoc Layer#process
    def process(self):
        super(RegistrationLayer, self).process()

        while True:
            d = self.lower_layer.receive(
                protocol=packets.RegistrationPacket.ETHERTYPE,
            )
            if d is None:
                break
            packet = packets.RegistrationPacket.decode(d.data)
            if packet.command == packet.COMMAND_ALLOCATE:
                self._name_repository.register_name(
                    name=packet.name,
                    mac=d.src,
                )
            elif packet.command == packet.COMMAND_RELEASE:
                self._name_repository.unregister_name(
                    name=packet.name,
                    mac=d.src,
                )

        now = time.time()
        if self._last_announce_time < now - self._ANNOUNCE_INTERVAL:
            self._last_announce_time = now
            self._announce(
                command=packets.RegistrationPacket.COMMAND_ALLOCATE,
            )

    ## Modify operation mode.
    def change_mode(self, mode):
        super(RegistrationLayer, self).change_mode(mode)

        if self.mode == self.MODE_STOPPING:
            self._announce(
                command=packets.RegistrationPacket.COMMAND_RELEASE,
            )


## Chat layer.
class ChatLayer(Layer):

    ## Prompt for edit mode.
    PROMPT_EDIT = '>'
    ## Prompt for standard mode.
    PROMPT_STANDARD = ':'

    ## Current edited message.
    _current_message = ''

    ## Send a string to higher layer.
    # @param s (str) string.
    #
    def _send_string(self, s):
        self.queue_receive(
            queued_data=self.QueuedData(
                data=s.encode('utf-8'),
                display=s,
            ),
        )

    ## Send a chat line.
    # @param name (str) chatter's name.
    # @param message (str) message.
    # @param prompt (optional, str) prompt to use before message.
    # @param valid (optional, bool) is chatter's name valid.
    # @param permanent (optional, bool) print new line at end of line.
    #
    # Erase current line, write name and message, with optional markers.
    #
    def _send_chat_line(
        self,
        name,
        message,
        prompt=None,
        valid=True,
        permanent=False,
    ):
        inner = '{name:14}{valid}{prompt} {message}'.format(
            name=name,
            message=message,
            prompt=prompt if prompt is not None else self.PROMPT_STANDARD,
            valid=' ' if valid else 'X',
        )
        self._send_string(
            (
                '\r{empty}\r'
                '{inner}{permanent}'
            ).format(
                empty=' ' * 79,
                inner=inner,
                permanent='\r\n' if permanent else '',
            )
        )
        if permanent:
            self.logger.info('Message: %s', inner)

    ## Refresh current prompt.
    #
    # Prints local chatter's line, handy when previous was overwritten.
    #
    def _refresh_prompt(self):
        self._send_chat_line(
            name=self._local_name,
            message=self._current_message,
            prompt=self.PROMPT_EDIT,
        )

    ## Constructor.
    # @param lower_layer (@ref Layer) lower layer to interact with.
    # @param mac_multicast (bytearray) mac to use as destination.
    # @param name_repository (@ref NameRepository) name repository to
    #   interact with.
    # @param local_name (str) local name to announce.
    #
    def __init__(
        self,
        lower_layer,
        mac_multicast,
        name_repository,
        local_name,
    ):
        super(ChatLayer, self).__init__(
            lower_layer=lower_layer,
        )
        self._mac_multicast = mac_multicast
        self._name_repository = name_repository
        self._local_name = local_name

        self.lower_layer.register_protocol(
            protocol=packets.ChatPacket.ETHERTYPE,
        )
        self._refresh_prompt()

    ## Destructor.
    def __del__(self):
        self.lower_layer.unregister_protocol(
            protocol=packets.ChatPacket.ETHERTYPE,
        )

    ## @copydoc Layer#__repr__
    def __repr__(self):
        return 'Chat Layer'

    ## @copydoc Layer#process
    def process(self):
        super(ChatLayer, self).process()

        while True:
            d = self.lower_layer.receive(
                protocol=packets.ChatPacket.ETHERTYPE,
            )
            if d is None or d.dst != self._mac_multicast:
                break
            packet = packets.ChatPacket.decode(d.data)
            self._send_chat_line(
                name=packet.name,
                message=packet.message,
                prompt=':',
                valid=self._name_repository.is_name_valid(
                    name=packet.name,
                    mac=d.src,
                ),
                permanent=True,
            )
            self._refresh_prompt()

        while True:
            d = self.dequeue_send()
            if d is None:
                break

            for c in d.data.decode('utf-8'):
                if c == '\r':
                    packet = packets.ChatPacket(
                        name=self._local_name,
                        message=self._current_message,
                    )
                    self.lower_layer.send(
                        queued_data=self.QueuedData(
                            protocol=packets.ChatPacket.ETHERTYPE,
                            dst=self._mac_multicast,
                            data=packet.encode(),
                            display=packet,
                        )
                    )
                    self._send_chat_line(
                        name=self._local_name,
                        message=self._current_message,
                        permanent=True,
                    )
                    self._current_message = ''
                    self._refresh_prompt()
                elif c in CHARS_BACKSPACE:
                    if self._current_message:
                        self._send_string('\b \b')
                        self._current_message = self._current_message[:-1]
                else:
                    self._send_string(c)
                    self._current_message += c

    ## Change operation mode.
    # @param mode (int) new operation mode.
    #
    def change_mode(self, mode):
        super(ChatLayer, self).change_mode(mode)

        if self.mode == self.MODE_STOPPING:
            self._send_string('\r\n')


## Terminal layer.
#
# Interacts with terminal.
#
class TerminalLayer(Layer):

    ## Constructor.
    # @param lower_layer (@ref Layer) lower layer to interact with.
    # @param input_char (gutil.Char) Char instance to interact with.
    # @param output_stream (file) stream to send output to.
    #
    def __init__(
        self,
        lower_layer,
        input_char,
        output_stream,
    ):
        super(TerminalLayer, self).__init__(
            lower_layer=lower_layer,
        )
        self._input_char = input_char
        self._output_stream = output_stream

    ## @copydoc Layer#__repr__
    def __repr__(self):
        return 'Terminal Layer'

    ## @copydoc Layer#process
    def process(self):
        super(TerminalLayer, self).process()

        while True:
            d = self.lower_layer.receive()
            if d is None:
                break

            self._output_stream.write(d.data.decode('utf-8'))
            self._output_stream.flush()

        while self.mode == self.MODE_NORMAL:
            c = self._input_char.getchar()
            if c is None:
                break
            if c == CHAR_ESCAPE:
                raise ExitException()

            self.lower_layer.send(
                queued_data=self.QueuedData(
                    data=c.encode('utf-8'),
                    display=c,
                )
            )


## Parse program argument.
# @returns (dict) program arguments.
#
def parse_args():

    LOG_STR_LEVELS = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL,
    }

    parser = argparse.ArgumentParser(
        prog=PACKAGE_NAME,
        description=(
            'multicast chat with impersonation prevention'
        ),
    )
    parser.add_argument(
        '--version',
        action='version',
        version=PACKAGE_VERSION,
    )
    parser.add_argument(
        '--log-level',
        dest='log_level_str',
        default='INFO',
        choices=LOG_STR_LEVELS.keys(),
        help='Log level',
    )
    parser.add_argument(
        '--log-file',
        dest='log_file',
        metavar='FILE',
        default=os.devnull,
        help='Logfile to write to, default: %(default)s',
    )
    parser.add_argument(
        '--interface',
        dest='interface',
        help='Interface name, default is first',
    )
    parser.add_argument(
        '--name',
        dest='name',
        required=True,
        help='Chat user name',
    )
    parser.add_argument(
        '--mac-local',
        dest='mac_local_string',
        required=True,
        metavar='MAC',
        help='Local Ethernet MAC address xx:xx:xx:xx:xx:xx',
    )
    parser.add_argument(
        '--mac-multicast',
        dest='mac_multicast_string',
        default=packets.EthernetPacket.mac_to_string(
            packets.EthernetPacket.MAC_BROADCAST,
        ),
        metavar='MAC',
        help=(
            'Multicast Ethernet MAC address xx:xx:xx:xx:xx:xx, '
            'default broadcast'
        ),
    )
    parser.add_argument(
        '--local-loopback-mode',
        dest='local_loopback_mode',
        default=False,
        action='store_true',
        help=(
            'Allows to run on same computer, debug only.'
        ),
    )
    args = parser.parse_args()
    args.log_level = LOG_STR_LEVELS[args.log_level_str]
    args.mac_local = packets.EthernetPacket.mac_from_string(
        args.mac_local_string,
    )
    args.mac_multicast = packets.EthernetPacket.mac_from_string(
        args.mac_multicast_string,
    )
    if args.interface is None:
        args.interface = gcap.GCap.get_interfaces()[0]['name']
    return args


## Main implementation.
def main():

    args = parse_args()

    logger = base.setup_logging(
        stream=open(args.log_file, 'a'),
        level=args.log_level,
    )
    logger.info('Startup %s-%s', PACKAGE_NAME, PACKAGE_VERSION)
    logger.debug('Args: %s', args)

    try:
        with gcap.GCap(iface=args.interface, timeout=GCAP_TIMEOUT) as cap:
            with gutil.Char() as char:
                name_repository = NameRepository()

                #
                # Construct layer hierarchy.
                #
                #   Terminal
                #       |
                #       |
                #       V
                #      Chat     Registration
                #        \        /
                #         |      |
                #         V      V
                #         Ethernet
                #            |
                #            |
                #            V
                #         Physical
                #

                logger.debug('Constructing layers')
                layers = []

                def _register_layer(e):
                    "Tiny local helper."
                    layers.append(e)
                    return e

                physical_layer = _register_layer(
                    PhysicalLayer(
                        cap=cap,
                    )
                )
                ethernet_layer = _register_layer(
                    EthernetLayer(
                        lower_layer=physical_layer,
                        address=args.mac_local,
                        local_loopback_mode=args.local_loopback_mode,
                    )
                )
                _register_layer(
                    RegistrationLayer(
                        lower_layer=ethernet_layer,
                        name_repository=name_repository,
                        local_name=args.name,
                    )
                )
                chat_layer = _register_layer(
                    ChatLayer(
                        lower_layer=ethernet_layer,
                        mac_multicast=args.mac_multicast,
                        name_repository=name_repository,
                        local_name=args.name,
                    )
                )
                _register_layer(
                    TerminalLayer(
                        lower_layer=chat_layer,
                        input_char=char,
                        output_stream=sys.stdout,
                    )
                )

                logger.debug('Procssing layers')
                try:
                    while True:
                        for layer in layers:
                            layer.process()
                        name_repository.housekeeping()
                except ExitException:
                    pass

                logger.debug('Notify stop')
                for layer in layers:
                    layer.change_mode(layer.MODE_STOPPING)

                logger.debug('Wait as long as processing')
                pending = True
                while pending:
                    pending = False
                    for layer in layers:
                        layer.process()
                        pending = pending or layer.has_work()
    except Exception as e:
        logger.error('Unexpected exception %s', e)
        logger.debug('Exception', exc_info=True)

        # this is how we format exceptions manually
        # can be simpler using traceback.print_exc()
        print("Unexpected exception %s" % e)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print("%s" % ''.join(
            traceback.format_exception(exc_type, exc_value, exc_traceback)
        ))


if __name__ == '__main__':
    main()


# vim: expandtab tabstop=4 shiftwidth=4

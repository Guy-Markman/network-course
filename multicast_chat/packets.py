# -*- coding: utf-8 -*-
## @package multicast_chat.packets Packets encoding/decoding.
## @file packets.py Implementation of @ref multicast_chat.packets
#


import re


from . import base


## Utilities for encoding/decoding.
#
class EncodeDecodeUtils(object):

    ## Decode octet string at n length.
    # @param buf (bytearray) buffer to decode.
    # @param n (int) number of octets.
    # @returns (tuple) first is parsed entry second is remaining.
    #
    @staticmethod
    def decode_binary(buf, n):
        return buf[:n], buf[n:]

    ## Decode ascii string at n length.
    # @param buf (bytearray) buffer to decode.
    # @param n (int) number of octets.
    # @param encoding (string, optional) text encoding.
    # @returns (tuple) first is parsed entry second is remaining.
    #
    @staticmethod
    def decode_string(buf, n, encoding='ascii'):
        return buf[:n].decode(encoding), buf[n:]

    ## Decode integer at n length big endian.
    # @param buf (bytearray) buffer to decode.
    # @param n (int) number of octets.
    # @returns (tuple) first is parsed entry second is remaining.
    #
    @staticmethod
    def decode_integer(buf, n):
        ret = 0
        for x in buf[:n]:
            ret = (ret << 8) + x
        return ret, buf[n:]

    ## Decode binary as hex string.
    # @param buf (bytearray) buffer to decode.
    # @param n (int) number of octets.
    # @param sep (optional, str) octet separator.
    # @returns (tuple) first is parsed entry second is remaining.
    #
    @staticmethod
    def decode_binary_as_hexstring(buf, n, sep=''):
        return sep.join('%02x' % x for x in buf[:n]), buf[n:]

    ## Encode binary.
    # @param x (bytearray) data to encode.
    # @param n (int) length to encode.
    # @returns (bytearray) data.
    #
    @staticmethod
    def encode_binary(x, n):
        return x[:n]

    ## Encode ascii string.
    # @param s (str) data to encode.
    # @returns (bytearray) data.
    #
    @staticmethod
    def encode_string(s):
        return s.encode('ascii')

    ## Encode big endian integer.
    # @param i (int) integer to encode.
    # @param n (int) octet length.
    # @returns (bytearray) data.
    #
    @staticmethod
    def encode_integer(i, n):
        l = []
        for x in range(n):
            l.append(i & 0xff)
            i >>= 8
        return bytearray(l[::-1])

    ## Encode binary out of hex string.
    # @param h (str) hex string.
    # @param sep (optional, str) octet separator.
    # @returns (bytearray) data.
    #
    @staticmethod
    def encode_binary_from_hexstring(h, sep=''):
        return bytearray(
            int(x, 16) for x in re.findall('..', h.replace(sep, ''))
        )


## Base for packet decoding/encoding.
#
class Packet(base.Base):

    ## Constructor.
    def __init__(self):
        super(Packet, self).__init__()

    ## String representation.
    def __repr__(self):
        return ''

    ## Equals operator.
    # @param other (object) other object.
    # @returns (bool) True if equals.
    #
    def __eq__(self, other):
        if type(self) is not type(other):
            return NotImplemented
        return True

    ## Encode as bytearray.
    # @returns (bytearray) encoded packet.
    # @throws RuntimeError If packet is incomplete.
    #
    def encode(self):
        return bytearray()

    ## Decode buffer to packet.
    # @param buf (bytearray: buffer to decode.
    # @returns (@ref EthernetPacket) packet.
    # @throws RuntimeError if buffer cannot buf parsed.
    #
    @staticmethod
    def decode(buf):
        pass


## Ethernet packet decoding/encoding.
#
class EthernetPacket(Packet):

    ## Return string representation of a mac address.
    # @param mac (bytearray) a mac.
    # @param sep (optional, str) octet separator.
    # @returns (str) String representation.
    #
    @staticmethod
    def mac_to_string(mac, sep=':'):
        return (
            None if mac is None
            else EncodeDecodeUtils.decode_binary_as_hexstring(
                mac,
                EthernetPacket.MAC_SIZE,
                sep=sep,
            )[0]
        )

    ## Returns mac out of string representation.
    # @param s (str) string.
    # @param sep (optional, str) octet separator.
    # @returns (bytearray) mac address.
    #
    @staticmethod
    def mac_from_string(s, sep=':'):
        return EncodeDecodeUtils.encode_binary_from_hexstring(s, sep)

    ## Returns True if mac address is a multicast address
    # @param mac (bytearray) mac address.
    # @returns (bool) True if multicast address.
    #
    @staticmethod
    def mac_is_multicast(mac):
        return (mac[0] & 0x01) != 0

    MAC_SIZE = 6            # MAC address size.
    ETHERTYPE_SIZE = 2      # Ethernet type size.
    MAX_SIZE = 1518         # Max packet size.
    MAC_BROADCAST = bytearray((0xff,) * MAC_SIZE)   # Broadcase address.

    ## Constructor.
    # @param dst (bytearray) destination address.
    # @param src (bytearray) source address.
    # @param ethertype (int) ethertype.
    # @param data (bytearray) payload.
    #
    def __init__(
        self,
        dst=None,
        src=None,
        ethertype=None,
        data=None,
    ):
        super(EthernetPacket, self).__init__()
        self.dst = dst
        self.src = src
        self.ethertype = ethertype
        self.data = None if data is None else bytearray(data)

    ## @copydoc Packet#__eq__
    def __eq__(self, other):
        if type(self) is not type(other):
            return NotImplemented

        return all((
            self.dst == other.dst,
            self.src == other.src,
            self.ethertype == other.ethertype,
            self.data == other.data,
        ))

    ## @copydoc Packet#__repr__
    def __repr__(self):
        return (
            '{{'
            '{super} '
            'EthernetPacket: '
            'dst: {dst}, '
            'src: {src}, '
            'ethertype: {ethertype} '
            'data: {data} '
            '}}'
        ).format(
            super=super(EthernetPacket, self).__repr__(),
            self=self,
            dst=self.mac_to_string(self.dst),
            src=self.mac_to_string(self.src),
            ethertype=(
                'N/A' if self.ethertype is None
                else '{0:04x}'.format(self.ethertype)
            ),
            data=(
                'N/A' if self.data is None
                else EncodeDecodeUtils.decode_binary_as_hexstring(
                    self.data,
                    None,
                )[0]
            ),
        )

    ## @copydoc Packet#encode
    def encode(self):
        if None in (
            self.dst,
            self.src,
            self.ethertype,
            self.data,
        ):
            raise RuntimeError('Incomplete ethernet packet')

        if len(self.dst) != self.MAC_SIZE:
            raise RuntimeError('Invalid destination MAC address')
        if len(self.src) != self.MAC_SIZE:
            raise RuntimeError('Invalid source MAC address')
        if (
            self.ethertype < 0 or
            self.ethertype >= 2 ** (8 * self.ETHERTYPE_SIZE)
        ):
            raise RuntimeError('Invalid ethertype value %s', self.ethertype)

        encoded = (
            EncodeDecodeUtils.encode_binary(
                self.dst,
                self.MAC_SIZE,
            ) +
            EncodeDecodeUtils.encode_binary(
                self.src,
                self.MAC_SIZE,
            ) +
            EncodeDecodeUtils.encode_integer(
                self.ethertype,
                self.ETHERTYPE_SIZE
            ) +
            self.data
        )

        if len(encoded) > self.MAX_SIZE:
            raise RuntimeError('Too large ethernet packet')

        return encoded

    ## @copydoc Packet#decode
    @staticmethod
    def decode(buf):
        packet = EthernetPacket()

        if len(buf) < packet.MAC_SIZE * 2 + packet.ETHERTYPE_SIZE:
            raise RuntimeError('Too small ethernet packet')
        if len(buf) > packet.MAX_SIZE:
            raise RuntimeError(
                (
                    'Too large ethernet packet at size {actual} '
                    'expected {expected}'
                ).format(
                    actual=len(buf),
                    expected=packet.MAX_SIZE,
                )
            )

        packet.dst, buf = EncodeDecodeUtils.decode_binary(
            buf,
            packet.MAC_SIZE,
        )
        packet.src, buf = EncodeDecodeUtils.decode_binary(
            buf,
            packet.MAC_SIZE,
        )
        packet.ethertype, buf = EncodeDecodeUtils.decode_integer(
            buf,
            packet.ETHERTYPE_SIZE,
        )
        packet.data, buf = EncodeDecodeUtils.decode_binary(
            buf,
            None
        )
        return packet


## Registration packet decoder/encoder.
#
class RegistrationPacket(Packet):

    ETHERTYPE = 0x1002      ## Ethernet type for registration packet.
    COMMAND_SIZE = 1        ## Command field size.
    NAME_SIZE = 10          ## Name field size.

    ## Commands
    (
        COMMAND_ALLOCATE,
        COMMAND_RELEASE,
    ) = range(2)

    ## Command mapping
    COMMAND_DESC = {
        COMMAND_ALLOCATE: 'allocate',
        COMMAND_RELEASE: 'release',
    }

    ## Constructor.
    # @param command (int) registration command.
    # @param name (str) announce name.
    #
    def __init__(
        self,
        command=None,
        name=None,
    ):
        super(RegistrationPacket, self).__init__()
        self.command = command
        self.name = name

    ## @copydoc Packet#__eq__
    def __eq__(self, other):
        if type(self) is not type(other):
            return NotImplemented

        return all((
            self.command == other.command,
            self.name == other.name,
        ))

    ## @copydoc Packet#__repr__
    def __repr__(self):
        return (
            '{{'
            '{super} '
            'RegistrationPacket: '
            'command: {command}, '
            'name: {self.name} '
            '}}'
        ).format(
            super=super(RegistrationPacket, self).__repr__(),
            self=self,
            command=self.COMMAND_DESC.get(
                self.command,
                'Invalid',
            ),
        )

    ## @copydoc Packet#encode
    def encode(self):
        if None in (
            self.command,
            self.name,
        ):
            raise RuntimeError('Incomplete registration packet')

        if self.command < 0 or self.command >= 2 ** (self.COMMAND_SIZE * 8):
            raise RuntimeError(
                (
                    'Invalid registration packet, '
                    'command {command} too large'
                ).format(
                    command=self.command,
                )
            )

        if self.command not in (
            self.COMMAND_ALLOCATE,
            self.COMMAND_RELEASE,
        ):
            raise RuntimeError(
                'Invalid registration packet, invalid command=%s',
                self.command,
            )

        return (
            EncodeDecodeUtils.encode_integer(
                self.command,
                self.COMMAND_SIZE,
            ) +
            EncodeDecodeUtils.encode_string(
                self.name[:self.NAME_SIZE].ljust(
                    self.NAME_SIZE
                )
            )
        )

    ## @copydoc Packet#decode
    @staticmethod
    def decode(buf):
        packet = RegistrationPacket()

        if len(buf) < packet.NAME_SIZE:
            raise RuntimeError('Invalid registration packet')

        packet.command, buf = EncodeDecodeUtils.decode_integer(
            buf,
            packet.COMMAND_SIZE,
        )
        packet.name, buf = EncodeDecodeUtils.decode_string(
            buf,
            packet.NAME_SIZE,
        )
        packet.name = packet.name.strip()
        return packet


## Chat packet decoder/encoder.
#
class ChatPacket(Packet):

    ETHERTYPE = 0x1001      ## Ethernet type for chat packet.
    NAME_SIZE = 10          ## Name field length.

    ## Constructor.
    # @param name (str) chatter's name.
    # @param message (str) message.
    #
    def __init__(
        self,
        name=None,
        message=None,
    ):
        super(ChatPacket, self).__init__()
        self.name = name
        self.message = message

    ## @copydoc Packet#__eq__
    def __eq__(self, other):
        if type(self) is not type(other):
            return NotImplemented

        return all((
            self.name == other.name,
            self.message == other.message,
        ))

    ## @copydoc Packet#__repr__
    def __repr__(self):
        return (
            '{{'
            '{super} '
            'ChatPacket: '
            'name: {self.name}, '
            'message: {self.message} '
            '}}'
        ).format(
            super=super(ChatPacket, self).__repr__(),
            self=self,
        )

    ## @copydoc Packet#encode
    def encode(self):
        if None in (self.name, self.message):
            raise RuntimeError('Incomplete chat packet')

        return (
            EncodeDecodeUtils.encode_string(
                self.name[:self.NAME_SIZE].ljust(
                    self.NAME_SIZE
                )
            ) +
            EncodeDecodeUtils.encode_string(self.message)
        )

    ## @copydoc Packet#decode
    @staticmethod
    def decode(buf):
        packet = ChatPacket()

        if len(buf) < packet.NAME_SIZE:
            raise RuntimeError('Invalid chat packet')

        packet.name, buf = EncodeDecodeUtils.decode_string(
            buf,
            packet.NAME_SIZE,
        )
        packet.name = packet.name.strip()
        packet.message, buf = EncodeDecodeUtils.decode_string(buf, None)
        return packet


# vim: expandtab tabstop=4 shiftwidth=4

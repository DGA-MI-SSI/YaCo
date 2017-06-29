#   Copyright (C) 2017 The YaCo Authors
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import idc
import logging


IDLE_PRIORITY_CLASS = 0x00000040
logger = logging.getLogger("YaCo")
debug = False


class YaTools(object):

    """
    classdocs
    """

    def __init__(self, addr_len=None):
        """
        Constructor
        """
        if addr_len is None:
            if idc.BADADDR == 0xFFFFFFFF:
                self.addr_len = 32
            elif idc.BADADDR == 0xFFFFFFFFFFFFFFFF:
                self.addr_len = 64
            else:
                logger.error('Bad address len : 0x%X' % idc.BADADDR)
        else:
            self.addr_len = addr_len

    def address_to_hex_string(self, address):
        if self.addr_len == 32:
            return "0x%08X" % address
        elif self.addr_len == 64:
            return "0x%016X" % address
        else:
            return hex(address)

    def try_read_hex_value(self, value):
        if value[0:2] == "0x":
            hex_forced = True
            value = value[2:]
        else:
            hex_forced = False

        if hex_forced or str.isdigit(value):
            if len(value) <= 8:
                return int(value, 16)
            elif len(value) <= 16:
                return int(value, 16)
            elif hex_forced:
                logger.warning("unable to parse hex value : '%s'" % value)
                return int(value, 16)

        return value

    def hex_string_to_address(self, hex_str):
        if hex_str[0:2] == "0x":
            hex_str = hex_str[2:]

        if self.addr_len == 32:
            return int(hex_str, 16)
        elif self.addr_len == 64:
            return int(hex_str, 16)
        else:
            logger.warning("unable to parse hex address : '%s'" % hex_str)
            return int(hex_str, 16)

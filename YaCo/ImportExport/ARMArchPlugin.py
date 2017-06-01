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

import logging
import idaapi

from DefaultArchPlugin import DefaultArchPlugin, \
    DefaultIDAModelPlugin

logger = logging.getLogger("YaCo")


class ARMIDAModelPlugin(DefaultIDAModelPlugin):
    def __init__(self):
        self.thumb_segment_register = idaapi.str2reg("T")

    def accept_basic_block_hook(self, visitor, basic_block, funcEA, func, parent_function_id):
        startEA = basic_block['startEA']
        thumb_flag = idaapi.getSR(startEA, self.thumb_segment_register)
        visitor.visit_attribute("thumb_mode_flag", str(thumb_flag))

    def accept_function_hook(self, visitor, eaFunc, func, basic_blocks=None):
        startEA = eaFunc
        thumb_flag = idaapi.getSR(startEA, self.thumb_segment_register)
        visitor.visit_attribute("thumb_mode_flag", str(thumb_flag))


class ARMIDAVisitorPlugin(object):
    def __init__(self):
        self.thumb_segment_register = idaapi.str2reg("T")

    def make_basic_block_prehook(self, object_version, address):
        pass

    def make_basic_block_posthook(self, object_version, address):
        address = object_version.get_object_address()
        size = object_version.get_size()

        try:
            thumb_flag = object_version.get_attributes()['thumb_mode_flag']
        except KeyError:
            thumb_flag = None

        current_thumb_flag = idaapi.getSR(address, self.thumb_segment_register)
        logger.debug("make_basic_block_posthook:thumb_flag = %d (vs %s in cache)" % (current_thumb_flag, thumb_flag))
        if thumb_flag is not None and current_thumb_flag != thumb_flag:
            idaapi.set_sreg_at_next_code(address, address + size, self.thumb_segment_register, int(thumb_flag))
            # 			idaapi.splitSRarea1(address, self.thumb_segment_register, int(thumb_flag), SR_user)

    def make_function_prehook(self, object_version, address):
        address = object_version.get_object_address()
        size = object_version.get_size()

        try:
            thumb_flag = object_version.get_attributes()['thumb_mode_flag']
        except KeyError:
            thumb_flag = None

        current_thumb_flag = idaapi.getSR(address, self.thumb_segment_register)
        logger.debug("make_function_prehook:thumb_flag = %d (vs %s in cache)" % (current_thumb_flag, thumb_flag))
        if thumb_flag is not None and current_thumb_flag != thumb_flag:
            idaapi.set_sreg_at_next_code(address, address + size, self.thumb_segment_register, int(thumb_flag))
            # 			idaapi.splitSRarea1(address, self.thumb_segment_register, int(thumb_flag), SR_user)

    def make_function_posthook(self, object_version, address):
        pass


class ARMArchPlugin(DefaultArchPlugin):
    '''
    classdocs
    '''

    def __init__(self, yatools):
        DefaultArchPlugin.__init__(self, yatools)

        self.ida_model_plugin = ARMIDAModelPlugin()
        self.ida_visitor_plugin = ARMIDAVisitorPlugin()

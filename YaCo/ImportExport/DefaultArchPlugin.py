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

class DefaultIDAModelPlugin(object):

    def accept_basic_block_hook(self, visitor, basic_block, funcEA, func, parent_function_id):
        pass

    def accept_function_hook(self, visitor, eaFunc, func, basic_blocks=None):
        pass


class DefaultIDAVisitorPlugin(object):

    def make_basic_block_prehook(self, object_version, address):
        pass

    def make_basic_block_posthook(self, object_version, address):
        pass

    def make_function_prehook(self, object_version, address):
        pass

    def make_function_posthook(self, object_version, address):
        pass


class DefaultArchPlugin(object):

    '''
    classdocs
    '''

    def __init__(self, yatools):
        self.yatools = yatools
        self.ida_model_plugin = DefaultIDAModelPlugin()
        self.ida_visitor_plugin = DefaultIDAVisitorPlugin()

    def get_ida_model_plugin(self):
        return self.ida_model_plugin

    def get_ida_visitor_plugin(self):
        return self.ida_visitor_plugin

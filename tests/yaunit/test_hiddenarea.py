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

import idaapi
import idc
import unittest
import yaunit

import logging
logger = logging.getLogger("YaCo")

class Fixture(unittest.TestCase):

    def yatest_hiddenareas(self):
        logger.info("yatest_hiddenarea")
        addrs = []
        for i in range(0, 3):
            addr = yaunit.get_next_function()
            logger.info("yatest_hiddenarea:0x%08X : %d", addr, i)
            ea2 = idaapi.nextaddr(addr)
            idaapi.add_hidden_area(addr, ea2, "yatest_hiddenarea_%x" % addr, "header", "footer", 0)
            addrs.append(addr)
        yaunit.save('hiddenarea', addrs)

    def check_hiddenarea(self, bookmark, addr):
        hidden_area = idaapi.get_hidden_area(addr)
        if hidden_area is None:
            self.assertTrue(False)
        self.assertEqual(hidden_area.description, bookmark)

    @unittest.skip("not implemented")
    def yacheck_hiddenareas(self):
        addrs = yaunit.load('hiddenarea')
        for i in range(0, 3):
            self.check_hiddenarea("yatest_hiddenarea_%x" % addrs[i], addrs[i])

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

    def yatest_bookmarks(self):
        logger.info("yatest_bookmarks")
        addrs = []
        for i in range(0, 3):
            addr = yaunit.get_next_function()
            logger.info("yatest_bookmarks:0x%08X : %d", addr, i)
            idc.MarkPosition(addr, 1, 1, 1, i+1, 'bookmark_%d' % i)
            addrs.append(addr)
        yaunit.save('bookmarks', addrs)

    def has_bookmark(self, bookmark, addr):
        for i in xrange(1, 1024):
            ea = idc.GetMarkedPos(i)
            self.assertNotEqual(ea, idaapi.BADADDR)
            if ea != addr:
                continue
            self.assertEqual(idc.GetMarkComment(i), bookmark)
            return True
        return False

    @unittest.skip("flaky")
    def yacheck_bookmarks(self):
        addrs = yaunit.load('bookmarks')
        for i in range(0, 3):
            self.assertTrue(self.has_bookmark('bookmark_%d' % i, addrs[i]))

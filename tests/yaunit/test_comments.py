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
import idautils
import sys

import logging
logger = logging.getLogger("YaCo")

# fn comment, fn repeatable, comment, repeatable, post, ant
tests = [
    ('aaa', '',     None,   None,   None,   None),
    ('',    'bbb',  None,   None,   None,   None),
    ('',    '',     'ccc',  None,   None,   None),
    ('',    '',     None,   'ddd',  None,   None),
    ('',    '',     None,   None,   'e\n#', None),
    ('',    '',     None,   None,   None,   'f\n#'),
    ('ggg', 'hhh',  'iii',  'jjj',  'kkk',  'lll'),
]

# comment, repeatable, post, ant
tests_data = [
    ('mmm', None,  None,   None),
    (None,  'nnn', None,   None),
    (None,  None,  'o\n#', None),
    (None,  None,  None,   'p\n#'),
    ('qqq', 'rrr', 'sss',  'tt'),
]

tests_code = tests_data

def get_func_item(offset):
    def get_item_(ea):
        items = list(idautils.FuncItems(ea))
        return offset < len(items)
    predicate = get_item_ if offset else None
    ea = yaunit.get_next_function(predicate)
    if not offset:
        return ea
    return list(idautils.FuncItems(ea))[offset]

def get_data_item():
    return yaunit.get_next_data()

def get_code_item():
    return yaunit.get_next_code()

# workaround ida 6.95 bugs...
class Fixture(unittest.TestCase):

    def try_ext_lin(self, operand, ea, n, line):
        try:
            self.assertEqual(operand(ea, n, line), None)
        except AttributeError:
            idc.SetFlags(ea, idc.GetFlags(ea) | idaapi.FF_LINE)

    def get_func_item(self, offset):
        while True:
            ea = get_func_item(offset)
            skip = False
            def getlen(x): return len(x) if x else 0
            for x in [False, True]:
                skip |= getlen(idc.get_func_cmt(ea, x))
                skip |= getlen(idc.get_cmt(ea, x))
            for x in [idc.E_PREV, idc.E_NEXT]:
                skip |= getlen(self.get_extra(ea, x))
            if not skip:
                return ea

    def yatest_comments(self):
        eas = []
        for offset in range(0, 3):
            for fn_cmt, fn_rpt, cmt, rpt, post, ant in tests:
                ea = self.get_func_item(offset)
                eas.append(ea)
                logger.debug("setting at 0x%08X : %r, %r, %r, %r, %r, %r" % (ea, fn_cmt, fn_rpt, cmt, rpt, post, ant))
                if len(fn_cmt):
                    self.assertEqual(idc.SetFunctionCmt(ea, fn_cmt, False), True)
                if len(fn_rpt):
                    self.assertEqual(idc.SetFunctionCmt(ea, fn_rpt, True), True)
                if cmt:
                    self.assertEqual(idc.MakeComm(ea, cmt), True)
                if rpt:
                    self.assertEqual(idc.MakeRptCmt(ea, rpt), True)
                if post:
                    for i, txt in enumerate(post.split('\n')):
                        self.try_ext_lin(idc.ExtLinB, ea, i, txt)
                if ant:
                    for i, txt in enumerate(ant.split('\n')):
                        self.try_ext_lin(idc.ExtLinA, ea, i, txt)
        yaunit.save('comments', eas)

    def get_extra(self, ea, start):
        j = 0
        d = []
        while True:
            x = idc.get_extra_cmt(ea, start + j)
            if x == None:
                break
            d.append(x)
            j += 1
        if not len(d):
            return None
        return "\n".join(d)

    def yacheck_comments(self):
        eas = yaunit.load('comments')
        i = 0
        for offset in range(0, 3):
            for fn_cmt, fn_rpt, cmt, rpt, post, ant in tests:
                ea = eas[i]
                logger.debug("checking at 0x%08X : %r, %r, %r, %r, %r, %r" % (ea, fn_cmt, fn_rpt, cmt, rpt, post, ant))
                i += 1
                self.assertEqual(idc.get_func_cmt(ea, False), fn_cmt)
                self.assertEqual(idc.get_func_cmt(ea, True), fn_rpt)
                self.assertEqual(idc.get_cmt(ea, False), cmt)
                self.assertEqual(idc.get_cmt(ea, True), rpt)
                self.assertEqual(self.get_extra(ea, idc.E_NEXT), post)
                self.assertEqual(self.get_extra(ea, idc.E_PREV), ant)

    def yatest_code_comments(self):
        eas = []
        for offset in range(0, 3):
            for cmt, rpt, post, ant in tests_code:
                ea = get_code_item()
                eas.append(ea)
                logger.debug("setting code comment at 0x%08X : %r, %r, %r, %r" % (ea, cmt, rpt, post, ant))
                if cmt:
                    self.assertEqual(idc.MakeComm(ea, cmt), True)
                if rpt:
                    self.assertEqual(idc.MakeRptCmt(ea, rpt), True)
                if post:
                    for i, txt in enumerate(post.split('\n')):
                        self.try_ext_lin(idc.ExtLinB, ea, i, txt)
                if ant:
                    for i, txt in enumerate(ant.split('\n')):
                        self.try_ext_lin(idc.ExtLinA, ea, i, txt)
        yaunit.save('code_comments', eas)

    def yacheck_code_comments(self):
        eas = yaunit.load('code_comments')
        i = 0
        for offset in range(0, 3):
            for cmt, rpt, post, ant in tests_code:
                ea = eas[i]
                logger.debug("checking code comment at 0x%08X : %r, %r, %r, %r" % (ea, cmt, rpt, post, ant))
                i += 1
                self.assertEqual(idc.get_cmt(ea, False), cmt)
                self.assertEqual(idc.get_cmt(ea, True), rpt)
                self.assertEqual(self.get_extra(ea, idc.E_NEXT), post)
                self.assertEqual(self.get_extra(ea, idc.E_PREV), ant)

    def yatest_data_comments(self):
        eas = []
        for offset in range(0, 3):
            for cmt, rpt, post, ant in tests_data:
                ea = get_data_item()
                eas.append(ea)
                logger.debug("setting data comment at 0x%08X : %r, %r, %r, %r" % (ea, cmt, rpt, post, ant))
                if cmt:
                    self.assertEqual(idc.MakeComm(ea, cmt), True)
                if rpt:
                    self.assertEqual(idc.MakeRptCmt(ea, rpt), True)
                if post:
                    for i, txt in enumerate(post.split('\n')):
                        self.try_ext_lin(idc.ExtLinB, ea, i, txt)
                if ant:
                    for i, txt in enumerate(ant.split('\n')):
                        self.try_ext_lin(idc.ExtLinA, ea, i, txt)
        yaunit.save('data_comments', eas)

    def yacheck_data_comments(self):
        eas = yaunit.load('data_comments')
        i = 0
        for offset in range(0, 3):
            for cmt, rpt, post, ant in tests_data:
                ea = eas[i]
                logger.debug("checking data comment at 0x%08X : %r, %r, %r, %r" % (ea, cmt, rpt, post, ant))
                i += 1
                self.assertEqual(idc.get_cmt(ea, False), cmt)
                self.assertEqual(idc.get_cmt(ea, True), rpt)
                self.assertEqual(self.get_extra(ea, idc.E_NEXT), post)
                self.assertEqual(self.get_extra(ea, idc.E_PREV), ant)

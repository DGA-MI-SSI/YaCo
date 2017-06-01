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
    ('aaa', None,   None,   None,   None,   None),
    (None,  'bbb',  None,   None,   None,   None),
    (None,  None,   'ccc',  None,   None,   None),
    (None,  None,   None,   'ddd',  None,   None),
    (None,  None,   None,   None,   'e\n#', None),
    (None,  None,   None,   None,   None,   'f\n#'),
    ('ggg', 'hhh',  'iii',  'jjj',  'kkk',  'lll'),
]

# comment, repeatable, post, ant
tests_data = [
    ('aaa', None,  None,   None),
    (None,  'bbb', None,   None),
    (None,  None,  'e\n#', None),
    (None,  None,  None,   'f\n#'),
    ('ggg', 'hhh', 'iii',  'jj'),
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
def try_ext_lin(operand, ea, n, line):
    try:
        operand(ea, n, line)
    except AttributeError:
        idc.SetFlags(ea, idc.GetFlags(ea) | idaapi.FF_LINE)

class Fixture(unittest.TestCase):

    def yatest_comments(self):
        eas = []
        for offset in range(0, 3):
            for fn_cmt, fn_rpt, cmt, rpt, post, ant in tests:
                ea = get_func_item(offset)
                eas.append(ea)
                logger.debug("setting at 0x%08X : %r, %r, %r, %r, %r, %r" % (ea, fn_cmt, fn_rpt, cmt, rpt, post, ant))
                if fn_cmt != None:
                    idc.SetFunctionCmt(ea, fn_cmt, False)
                if fn_rpt != None:
                    idc.SetFunctionCmt(ea, fn_rpt, True)
                if cmt != None:
                    idc.MakeComm(ea, cmt)
                if rpt != None:
                    idc.MakeRptCmt(ea, rpt)
                if post != None:
                    for i, txt in enumerate(post.split('\n')):
                        try_ext_lin(idc.ExtLinB, ea, i, txt)
                if ant != None:
                    for i, txt in enumerate(ant.split('\n')):
                        try_ext_lin(idc.ExtLinA, ea, i, txt)
        yaunit.save('comments', eas)

    @unittest.skipIf(sys.platform == "linux2", "unsupported")
    def yacheck_comments(self):
        eas = yaunit.load('comments')
        i = 0
        for offset in range(0, 3):
            for fn_cmt, fn_rpt, cmt, rpt, post, ant in tests:
                ea = eas[i]
                logger.debug("checking at 0x%08X : %r, %r, %r, %r, %r, %r" % (ea, fn_cmt, fn_rpt, cmt, rpt, post, ant))
                i += 1
                if fn_cmt != None:
                    self.assertEqual(idc.GetFunctionCmt(ea, False), fn_cmt)
                if fn_rpt != None:
                    self.assertEqual(idc.GetFunctionCmt(ea, True), fn_rpt)
                if cmt != None:
                    self.assertEqual(idc.GetCommentEx(ea, False), cmt)
                if rpt != None:
                    self.assertEqual(idc.GetCommentEx(ea, True), rpt)
                if post != None:
                    for j, txt in enumerate(post.split('\n')):
                        self.assertEqual(idc.LineB(ea, j), txt)
                if ant != None:
                    for j, txt in enumerate(ant.split('\n')):
                        self.assertEqual(idc.LineA(ea, j), txt)

    def yatest_code_comments(self):
        eas = []
        for offset in range(0, 3):
            for cmt, rpt, post, ant in tests_code:
                ea = get_code_item()
                eas.append(ea)
                logger.debug("setting code comment at 0x%08X : %r, %r, %r, %r" % (ea, cmt, rpt, post, ant))
                if cmt != None:
                    idc.MakeComm(ea, cmt)
                if rpt != None:
                    idc.MakeRptCmt(ea, rpt)
                if post != None:
                    for i, txt in enumerate(post.split('\n')):
                        try_ext_lin(idc.ExtLinB, ea, i, txt)
                if ant != None:
                    for i, txt in enumerate(ant.split('\n')):
                        try_ext_lin(idc.ExtLinA, ea, i, txt)
        yaunit.save('code_comments', eas)

    def yacheck_code_comments(self):
        eas = yaunit.load('code_comments')
        i = 0
        for offset in range(0, 3):
            for cmt, rpt, post, ant in tests_code:
                ea = eas[i]
                logger.debug("checking code comment at 0x%08X : %r, %r, %r, %r" % (ea, cmt, rpt, post, ant))
                i += 1
                if cmt != None:
                    self.assertEqual(idc.GetCommentEx(ea, False), cmt)
                if rpt != None:
                    self.assertEqual(idc.GetCommentEx(ea, True), rpt)
                if post != None:
                    for j, txt in enumerate(post.split('\n')):
                        self.assertEqual(idc.LineB(ea, j), txt)
                if ant != None:
                    for j, txt in enumerate(ant.split('\n')):
                        self.assertEqual(idc.LineA(ea, j), txt)

    def yatest_data_comments(self):
        eas = []
        for offset in range(0, 3):
            for cmt, rpt, post, ant in tests_data:
                ea = get_data_item()
                eas.append(ea)
                logger.debug("setting data comment at 0x%08X : %r, %r, %r, %r" % (ea, cmt, rpt, post, ant))
                if cmt != None:
                    idc.MakeComm(ea, cmt)
                if rpt != None:
                    idc.MakeRptCmt(ea, rpt)
                if post != None:
                    for i, txt in enumerate(post.split('\n')):
                        try_ext_lin(idc.ExtLinB, ea, i, txt)
                if ant != None:
                    for i, txt in enumerate(ant.split('\n')):
                        try_ext_lin(idc.ExtLinA, ea, i, txt)
        yaunit.save('data_comments', eas)

    @unittest.skipIf(sys.platform == "linux2", "unsupported")
    def yacheck_data_comments(self):
        eas = yaunit.load('data_comments')
        i = 0
        for offset in range(0, 3):
            for cmt, rpt, post, ant in tests_data:
                ea = eas[i]
                logger.debug("checking data comment at 0x%08X : %r, %r, %r, %r" % (ea, cmt, rpt, post, ant))
                i += 1
                if cmt != None:
                    self.assertEqual(idc.GetCommentEx(ea, False), cmt)
                if rpt != None:
                    self.assertEqual(idc.GetCommentEx(ea, True), rpt)
                if post != None:
                    for j, txt in enumerate(post.split('\n')):
                        self.assertEqual(idc.LineB(ea, j), txt)
                if ant != None:
                    for j, txt in enumerate(ant.split('\n')):
                        self.assertEqual(idc.LineA(ea, j), txt)

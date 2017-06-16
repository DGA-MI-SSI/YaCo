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
import re
import string
import traceback

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

logger = logging.getLogger("YaCo")

CALL_CONVENTIONS = set([
    "stdcall",
    "cdecl",
    "fastcall",
    "usercall",
    "thiscall",
])
_c1 = ["_" + str(x) for x in CALL_CONVENTIONS]
_c2 = ["__" + str(x) for x in CALL_CONVENTIONS]
CALL_CONVENTIONS.update(_c1, _c2)

PROTO_INVALID_ELEMENTS = set([
    # C/C++ keywords
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "char16_t",
    "char32_t",
    "class",
    "compl",
    "const",
    "constexpr",
    "const_cast",
    "continue",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "register",
    "reinterpret_cast",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq",
    # C++ optionnal
    "override",
    "final",
    # C++ reserved
    "posix",
    # windows-like types
    "byte",
    "ubyte",
    "short",
    "ushort",
    "word",
    "dword",
    "qword",
    "uword",
    "udword",
    "uqword",
    "wchar",
    "uwchar",
    "twchar",
    "lpcwstr",
    "hlocal",
    # stdint types
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "int128_t",
    "int256_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uint128_t",
    "uint256_t",
    "__int8",
    "__int16",
    "__int32",
    "__int64",
    "__int128",
    "__int256",
    "__uint8",
    "__uint16",
    "__uint32",
    "__uint64",
    "__uint128",
    "__uint256",
    # other
    "boolean",
    "exception",
    "size_t",
    "ssize_t",
    "",
]
)
# convention call
PROTO_INVALID_ELEMENTS.update(CALL_CONVENTIONS)

PROTOTYPE_DELIMITERS = [" ", ",", "*", "(", ")", ";", "&", "."]
PROTOTYPE_DELIMITERS_ESC = [" ", ",", "\*", "\(", "\)", ";", "&", "\."]
PROTOTYPE_REGEX = "|".join(PROTOTYPE_DELIMITERS_ESC)
PROTOTYPE_SPLITTER = re.compile("(" + PROTOTYPE_REGEX + ")", 0)


class YaToolPrototypeParser(object):
    """
    classdocs
    """

    def __init__(self):
        """
        Constructor
        """

    def parse_proto_for_hashes(self, proto):
        protos = set()
        idx = proto.find("%")
        while idx != -1:
            end = proto.find("%", idx + 1)
            if end == -1:
                logger.error("error while searching end at %d in '%s'" % (idx, proto))
                return None
            this_proto = proto[idx + 1:end]
            sharp = this_proto.find("#")
            protos.add((this_proto[:sharp], this_proto[sharp + 1:]))
            idx = proto.find("%", end + 1)

        logger.debug("parsed proto : %r" % protos)
        return protos

    def parse_proto(self, proto, obj_name):
        parsed_elements = self.get_proto_valid_names(proto, obj_name)

        valid_elements = set()
        for (el, is_valid) in parsed_elements:
            if is_valid:
                valid_elements.add(el)

        return valid_elements

    def split_proto(self, proto):
        return PROTOTYPE_SPLITTER.split(proto)

    def get_proto_valid_names(self, proto, obj_name=None):
        elements = self.split_proto(proto)
        skip_next = False

        parsed_elements = []

        for el in elements:
            in_invalids = False
            valid_name = False
            # handle the (valid case) "struct foo_t* arg_X"
            # where foo_t does not exist in structures
            is_digit = all(c in string.digits for c in el)
            if len(el) == 0:
                pass
            if el in PROTOTYPE_DELIMITERS:
                pass
            elif is_digit:
                pass
            elif obj_name is not None and el == obj_name:
                pass
            elif obj_name is None and (el[:4] == "sub_" or el[:8] == "nullsub_"):
                pass
            elif el.lower() in PROTO_INVALID_ELEMENTS:
                # if the name is a keyword, the next token should be the argument
                # name (or eventually another keyword)
                # this handles "unsigned int arg_foo", "uint arg_foo"
                in_invalids = True
                pass
            elif skip_next:
                pass
            else:
                # When a valid name is found, the next one is the name of the argument
                valid_name = True

            parsed_elements.append((el, valid_name))

            # -if el is "(", the next token must NOT be skipped
            # -if the name is valid, the next token won't be a valid name
            #  (it might very likely be the argument name)
            # -if el is in the invalid_list, the next token might be another keyword,
            #  or the argument name
            # -if el is "struct", the next token is a valid name, but need not be in the
            #  dependencies
            if len(el) > 0:
                if el not in PROTOTYPE_DELIMITERS:
                    skip_next = valid_name or in_invalids or el == "struct"
                elif el == "(" or el == ",":
                    skip_next = False

                # 			logger.debug("skip_next=%d, el:'%s'" % (skip_next, el))

        return parsed_elements

    """
    The following code fixes a bug in IDA, where GetType does not include
    the name of the object :
    '__int64 __fastcall(struc_1 *arg_foo)'
    must be changed to
    '__int64 __fastcall function_name(struc_1 *arg_foo)'
    We must add it before an openning parenthesis
    Finding the calling convention, then looking for the parenthesis
    ensures that we deal with the case where the return type
    is a function pointer
    Actually, we must find the opening parenthesis matching the last closing
    parenthesis, and look just before it.
    """

    def fix_function_prototype(self, function_type, function_name):
        if function_type[len(function_type) - 1:] != ")":
            logger.error("Last char of function type is not a closing parenthesis : '%s' (fn='%s')" %
                         (function_type, function_name))
            return function_type

        open_nb = 0
        close_nb = 1
        i = len(function_type) - 2
        while open_nb != close_nb and i > 0:
            this_char = function_type[i]
            if this_char == "(":
                open_nb += 1
            elif this_char == ")":
                close_nb += 1

            i -= 1

        if i == 0:
            logger.error("could not find correct openning parenthesis : '%s' (fn='%s'), open_nb=%d, close_nb=%d" %
                         (function_type, function_name, open_nb, close_nb))
            return
        # i now contains the position of the openning parenthesis of the arguments (minus 1)
        arg_open = i + 1
        # strip spaces before parenthesis
        while not str.isalnum(function_type[i]) and i >= 0:
            i -= 1
        last_token_end = i + 1

        while str.isalnum(function_type[i]) and i >= 0:
            i -= 1
        if i < 0:
            # the prototype is like "return_type(args)" : there is no token otherwise
            pass
        # 			logger.error("could not find good token before args : '%s' (fn='%s'), open_nb=%d,
        #               close_nb=%d, arg_open=%d" % (function_type, function_name, open_nb, close_nb, arg_open))
        # 			return function_type
        # i now points to the first char before the function name or the convention name
        last_token = function_type[i + 1:last_token_end]
        if last_token == function_name:
            return function_type

        else:
            orig_type = function_type
            function_type = "%s %s%s" % (
                function_type[:arg_open],
                function_name,
                function_type[arg_open:]
            )
            logger.debug("changed item type : '%s' -> '%s'" % (orig_type, function_type))

        return function_type

    def get_struc_enum_id_for_name(self, hash_provider, name):
        item_id = idc.GetStrucIdByName(name)
        if item_id == idc.BADADDR:
            item_id = idc.GetEnum(name)
            if item_id == idc.BADADDR:
                logger.error("no struc or enum id for name : %s", name)
                return None
        return hash_provider.get_struc_enum_object_id(item_id, name)

    """
    take a prototype and replace enum and struc names with their hashes
    """

    def update_prototype_with_hashes(self, proto, hash_provider, obj_name):
        try:
            parsed_elements = self.get_proto_valid_names(proto, obj_name)

            new_prototype = ""
            dependencies = list()
            for (el, is_valid) in parsed_elements:
                if is_valid:
                    hashed = self.get_struc_enum_id_for_name(hash_provider, el)
                    if hashed is not None:
                        h = hash_provider.hash_to_string(hashed)
                        new_prototype += el + " /*%" + el + "#" + h + "%*/"
                        dependencies.append((h, idc.GetStrucIdByName(el)))
                    else:
                        new_prototype += el
                else:
                    new_prototype += el

            logger.debug("prototype updated from '%s' to '%s'" % (proto, new_prototype))
            return (new_prototype, dependencies)
        except:
            traceback.print_exc()
            logger.error("Error while parsing prototype : '%s' (object_name=%s" % (proto, obj_name))
            return (proto, list())

    def update_data_prototype_with_hashes(self, proto, hash_provider):
        parsed_elements = self.get_proto_valid_names(proto)

        new_prototype = ""
        for (el, is_valid) in parsed_elements:
            if is_valid:
                hashed = self.get_struc_enum_id_for_name(hash_provider, el)
                if hashed is not None:
                    new_prototype += el + " /*%" + el + "#" + hash_provider.hash_to_string(hashed) + "%*/"
                else:
                    new_prototype += el
            else:
                new_prototype += el

        if proto != new_prototype:
            logger.debug("prototype updated from '%s' to '%s'" % (proto, new_prototype))
        return new_prototype

    def fix_struc_in_prototype(self, proto, struc_ids):
        current_pos = 0
        while proto.find("/*%", current_pos) != -1:
            start_comm = proto.find("/*%", current_pos)
            end_comm = proto.find("%*/", start_comm + 3)
            sharp = proto.find("#", start_comm + 3)
            struc_name = proto[start_comm + 3:sharp]
            object_id_str = proto[sharp + 1:end_comm]
            object_id = ya.YaToolObjectId_From_String(object_id_str)

            try:
                struc_id = struc_ids[object_id]
            except KeyError:
                logger.error("Bad object id str for struc in prototype : %s (in '%s')" % (object_id_str, proto))
                return proto
            new_struc_name = idc.GetStrucName(struc_id)
            if new_struc_name != struc_name:
                orig_proto = proto
                proto = proto.replace(struc_name, new_struc_name)
                logger.debug("Updated proto from '%s' to '%s'" % (orig_proto, proto))
                current_pos = 0
            else:
                current_pos = end_comm + 2

        return proto

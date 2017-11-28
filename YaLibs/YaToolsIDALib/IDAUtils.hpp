//  Copyright (C) 2017 The YaCo Authors
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <string>

#include "Logger.h"
#include "Yatools.h"
#include "Ida.h"

#ifdef __EA64__
#define EA_PREFIX   "ll"
#define EA_SIZE     "16"
#else
#define EA_PREFIX   ""
#define EA_SIZE     "8"
#endif
#define EA_FMT      "%0" EA_SIZE EA_PREFIX "X"

//#define MODULE_NAME "module_name"

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)(MODULE_NAME, (FMT "\n"), ## __VA_ARGS__)

#define YACO_IDA_MSG_PREFIX "yaco: "

#define IDA_LOG_WITH(TYPE, FMT, IDA_FN, IDA_PREFIX, ...) do {\
    LOG(TYPE, FMT, ## __VA_ARGS__); \
    (IDA_FN)(IDA_PREFIX FMT "\n", ## __VA_ARGS__); \
} while(0)

#define IDA_LOG_INFO(FMT, ...)      IDA_LOG_WITH(INFO, FMT, msg, YACO_IDA_MSG_PREFIX, ## __VA_ARGS__)
#define IDA_LOG_WARNING(FMT, ...)   IDA_LOG_WITH(WARNING, FMT, msg, YACO_IDA_MSG_PREFIX "WARNING: ", ## __VA_ARGS__)
#define IDA_LOG_ERROR(FMT, ...)     IDA_LOG_WITH(ERROR, FMT, msg, YACO_IDA_MSG_PREFIX "ERROR: ", ## __VA_ARGS__)

#define IDA_LOG_GUI_WARNING(FMT, ...) do{ \
    IDA_LOG_WARNING(FMT, ## __VA_ARGS__); \
    warning(FMT, ## __VA_ARGS__); \
} while(0)

#define IDA_LOG_GUI_ERROR(FMT, ...) do{ \
    IDA_LOG_ERROR(FMT, ## __VA_ARGS__); \
    error(FMT, ## __VA_ARGS__); \
} while(0)

std::string ea_to_hex(ea_t ea);

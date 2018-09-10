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

#include "Random.hpp"

#include <git2.h>

namespace
{
    // required to call _libssh2_mbedtls_random
    struct LibGit
    {
        LibGit()
        {
            git_libgit2_init();
        }

        ~LibGit()
        {
            git_libgit2_shutdown();
        }
    };
    static const LibGit libgit;
}

extern "C"
{
    // FIXME hackish, forward declare private function from src/mbedtls.h
    int _libssh2_mbedtls_random(unsigned char *buf, int len);
}

namespace rng
{
    void generate(void* pvdst, size_t szdst)
    {
        unsigned char* pdst = reinterpret_cast<unsigned char*>(pvdst);
        _libssh2_mbedtls_random(pdst, static_cast<int>(szdst));
    }
}
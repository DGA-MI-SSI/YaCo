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

#ifndef _MSC_VER
// disable warnings from external headers
#pragma GCC system_header
#pragma clang system_header
#endif

#include <git2.h>
#include <git2/errors.h>

static git_clone_options make_git_clone_options()
{
    git_clone_options opts = GIT_CLONE_OPTIONS_INIT;
    return opts;
}

static git_fetch_options make_git_fetch_options()
{
    git_fetch_options opts = GIT_FETCH_OPTIONS_INIT;
    return opts;
}

static git_checkout_options make_git_checkout_options()
{
    git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
    return opts;
}

static git_merge_options make_git_merge_options()
{
    git_merge_options opts = GIT_MERGE_OPTIONS_INIT;
    return opts;
}

static git_rebase_options make_git_rebase_options()
{
    git_rebase_options opts = GIT_REBASE_OPTIONS_INIT;
    return opts;
}

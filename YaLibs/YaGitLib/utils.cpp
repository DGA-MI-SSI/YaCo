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

#include "utils.hpp"

#include <stdio.h>
#include <fcntl.h>
#include <sstream>

#ifdef _MSC_VER
#   include <io.h>
#   include <filesystem>
#   define open     _open
#   define fdopen   _fdopen
#   define close    _close
#   define O_WRONLY _O_WRONLY
#   define O_CREAT  _O_CREAT
#   define O_EXCL   _O_EXCL
#   define S_IRUSR  S_IREAD
#   define S_IWUSR  S_IWRITE
#else
#   include <experimental/filesystem>
#   include <unistd.h>
#endif

namespace
{
struct FileDescriptor : public File_ABC
{
    FileDescriptor(const std::string& path, FILE* fh)
        : path(path)
        , fh(fh)
    {
    }

    ~FileDescriptor()
    {
        if(!fh)
            return;

        std::error_code err;
        std::experimental::filesystem::remove_all(path, err);
    }

    bool IsValid() const
    {
        return !!fh;
    }

    void Write(const char* line) const
    {
        fprintf(fh, "%s\n", line);
    }

    void Flush() const
    {
      fflush(fh);
    }

    const std::string& GetPath() const
    {
        return path;
    }

    void Close() const
    {
      if(!fh)
        return;

      fclose(fh);
    }

    std::string path;
    FILE*       fh;
};
}

std::shared_ptr<File_ABC> CreateTempFile()
{
    const auto base = std::experimental::filesystem::temp_directory_path();
    for(size_t i = 0; i < UINT16_MAX; ++i)
    {
        std::stringstream tmp;
        tmp << "tmp" << std::hex << i;
        const auto path = base / tmp.str();
        const int fd = open(path.string().data(), O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if(fd == -1)
            continue;
        const auto fh = fdopen(fd, "wb");
        if(!fh)
        {
            close(fd);
            continue;
        }
        return std::make_shared<FileDescriptor>(path.string(), fh);
    }
    return nullptr;
}

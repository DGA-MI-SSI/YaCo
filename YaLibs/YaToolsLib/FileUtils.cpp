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

#include "FileUtils.hpp"
#include "FlatBufferModel.hpp"
#include "FlatBufferVisitor.hpp"
#include "XmlAccept.hpp"

#include <memory>
#include <sstream>
#include <string>

#include <stdio.h>
#include <fcntl.h>

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

namespace fs = std::experimental::filesystem;

#ifdef WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
#   include <shlwapi.h>

namespace
{
struct Mmap : public Mmap_ABC
{
    Mmap(const char* pPath);

    const void* Get() const;
    size_t      GetSize() const;

private:
    std::shared_ptr<void> File;
    std::shared_ptr<void> Mapping;
    std::shared_ptr<void> View;
};
}

static void TryCloseHandle(HANDLE hValue)
{
    if(hValue && hValue != INVALID_HANDLE_VALUE)
        CloseHandle(hValue);
}

static void TryUnmapViewOfFile(void* pValue)
{
    if(pValue)
        UnmapViewOfFile(pValue);
}

Mmap::Mmap(const char* pPath)
{
    HANDLE hFile;
    HANDLE hMap;
    void*  pView;

    // open file
    hFile = CreateFile(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(hFile == INVALID_HANDLE_VALUE)
        return;
    File.reset(hFile, &TryCloseHandle);

    // create file mapping
    hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, nullptr);
    if(!hMap)
        return;
    Mapping.reset(hMap, &TryCloseHandle);

    // create map view
    pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if(!pView)
        return;
    View.reset(pView, &TryUnmapViewOfFile);
}

const void* Mmap::Get() const
{
    return View ? View.get() : nullptr;
}

size_t Mmap::GetSize() const
{
    LARGE_INTEGER Size;
    if(!GetFileSizeEx(File.get(), &Size))
        return 0;
    return static_cast<size_t>(Size.QuadPart);
}

#else
#   include <sys/mman.h>
#   include <sys/stat.h>
#   include <fcntl.h>
#   include <unistd.h>

namespace
{
struct Fd
{
    Fd(int fd)
     : fd(fd)
    {
    }
    ~Fd()
    {
        if(fd != -1)
            close(fd);
    }
    int fd;
};

struct Mmap : public Mmap_ABC
{
    Mmap(const char* pPath);

    const void* Get() const;
    size_t      GetSize() const;

private:
    std::shared_ptr<Fd>   File;
    std::shared_ptr<void> View;
};
}

Mmap::Mmap(const char* pPath)
{
    struct stat sb;

    const auto fd_input = open(pPath, O_RDONLY);
    if(fd_input == -1)
    {
        return;
    }
    File = std::make_shared<Fd>(fd_input);

    if(fstat(fd_input, &sb) == -1)
    {
        return;
    }
    const auto input_size = sb.st_size;


    const auto pbuffer = mmap(nullptr, input_size, PROT_READ, MAP_PRIVATE, fd_input, 0);

    if(pbuffer == MAP_FAILED)
    {
        return;
    }
    View.reset(pbuffer, [=](void* mem)
            {
        if(mem != MAP_FAILED)
        {
            munmap(mem, input_size);
        }
            });
}

const void* Mmap::Get() const
{
    return View ? View.get() : nullptr;
}

size_t Mmap::GetSize() const
{
    struct stat sb;
    if(fstat(File->fd, &sb) == -1)
    {
        return -1;
    }
    return sb.st_size;
}
#endif

std::shared_ptr<Mmap_ABC> MmapFile(const char* pPath)
{
    return std::make_shared<Mmap>(pPath);
}

#ifdef WIN32
#pragma comment(lib, "rpcrt4.lib")
#include "rpc.h"

std::string CreateTemporaryDirectory(const std::string& base)
{
    auto path = base + "/";
    UUID uuid;
    if(UuidCreate(&uuid) != RPC_S_OK)
        throw std::runtime_error("unable to create uuid");

    RPC_CSTR str = nullptr;
    if(UuidToString(&uuid, &str) != RPC_S_OK)
        throw std::runtime_error("unable to convert uuid to string");

    path += reinterpret_cast<const char*>(str);
    RpcStringFree(&str);

    std::error_code err;
    fs::create_directories(path, err);
    if(err)
        throw std::runtime_error("unable to create directories");

    return path;
}
#else
std::string CreateTemporaryDirectory(const std::string& base)
{
    std::string strvalue = base + "_XXXXXX";
    std::vector<char> value;
    value.resize(strvalue.size() + 1);
    memcpy(&value[0], strvalue.data(), strvalue.size());
    const auto ptr = mkdtemp(&value[0]);
    if(!ptr)
        throw std::runtime_error("unable to mkdtemp");
    return ptr;
}
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
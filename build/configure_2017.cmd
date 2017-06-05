@echo off
set OUT=..\out\x86
mkdir %OUT% 2>NUL
set TARGET="Visual Studio 15 2017"
set CFGS=Debug;RelWithDebInfo
cmd /C "pushd %OUT% & cmake ../../build -G %TARGET% -DCMAKE_CONFIGURATION_TYPES=%CFGS%"

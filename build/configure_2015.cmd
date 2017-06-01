@echo off
set OUT=..\out\x86
mkdir %OUT% 2>NUL
set TARGET="Visual Studio 14 2015"
set PLATFORM=v140
set CFGS=Debug;RelWithDebInfo
cmd /C "pushd %OUT% & cmake ../../build -G %TARGET% -T %PLATFORM% -DCMAKE_CONFIGURATION_TYPES=%CFGS%"

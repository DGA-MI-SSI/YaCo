@echo off

set ROOT_DIR=%~dp0..
echo %ROOT_DIR%

rem plugins
mklink yaco_plugin.py %ROOT_DIR%\YaCo\yaco_plugin.py

rem yatools
mklink /D YaTools %ROOT_DIR%\bin\yaco_x64\YaTools

@echo off

set ROOT_DIR=%~dp0..
echo %ROOT_DIR%

rem plugins
mklink /H yaco_plugin.py %ROOT_DIR%\YaCo\yaco_plugin.py

rem yatools
mklink /J /D YaTools %ROOT_DIR%\bin\yaco_x64\YaTools

rem yaco
mklink /J /D YaTools\YaCo %ROOT_DIR%\YaCo

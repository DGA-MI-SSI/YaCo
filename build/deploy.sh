#!/bin/sh

export ROOT_DIR=`dirname $0`/..

# plugin
ln -s $ROOT_DIR/YaCo/yaco_plugin.py

# yatools
ln -s $ROOT_DIR/bin/yaco_x86/YaTools

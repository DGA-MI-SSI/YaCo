#!/bin/sh

export ROOT_DIR=`dirname $0`/..

# plugin
ln -s $ROOT_DIR/YaCo/yaco_plugin.py

# yatools
mkdir -p YaTools
ln -s $ROOT_DIR/bin/yaco_d_x64/YaTools/bin YaTools/
ln -s $ROOT_DIR/YaCo YaTools/

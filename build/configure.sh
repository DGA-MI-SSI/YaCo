#!/bin/bash

if [ -z "$TARGET" ]
then
    TARGET="Unix Makefiles"
fi
echo TARGET=$TARGET [Unix Makefiles, Ninja]

if [ -z "$CONFIG" ]
then
    CONFIG=Release
fi
echo CONFIG=$CONFIG [Debug, Release]

if [ -z "$OUT" ]
then
    OUT=../out/x64_$CONFIG
fi
echo OUT=$OUT

FLAGS="-fPIC -pg"
C_FLAGS="${CMAKE_C_FLAGS} $FLAGS"
CXX_FLAGS="${CMAKE_CXX_FLAGS} $FLAGS"

mkdir -p $OUT
cd $OUT
cmake ../../build -G "$TARGET" -DCMAKE_BUILD_TYPE="${CONFIG}" -DCMAKE_C_FLAGS="${C_FLAGS}" -DCMAKE_CXX_FLAGS="${CXX_FLAGS}"
cd ../../build

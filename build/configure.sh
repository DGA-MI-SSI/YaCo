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

if [ -z "$ARCH" ]
then
    ARCH=$(uname -m)
fi
echo ARCH=$ARCH [x86, x86_64, x64]

FLAGS=""
if [ "$ARCH" == "x86_64" ]
then
    FLAGS="$FLAGS -m32"
fi
if [ "$ARCH" == "x64" ]
then
    FLAGS="-fPIC"
fi

if [ -z "$OUT" ]
then
    OUT=../out/${ARCH}_$CONFIG
fi
echo OUT=$OUT

CMAKE_C_FLAGS="${CMAKE_C_FLAGS} $FLAGS -pg"
CMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS} $FLAGS -pg"

mkdir -p $OUT
cd $OUT
cmake ../../build -G "$TARGET" -DCMAKE_BUILD_TYPE="${CONFIG}" -DCMAKE_C_FLAGS="${CMAKE_C_FLAGS}" -DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS}"
cd ../../build

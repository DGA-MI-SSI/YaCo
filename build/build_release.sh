#!/bin/bash

YATOOLS_VERSION=v1.3
GIT_REF=origin/v1.3
GIT_URL=ssh://gitolite@repo/YaTools
GIT_URL_BIN=${GIT_URL}-bin
GIT_URL_DIR=YaTools-bin

rm -rf /tmp/TMP_RELEASE 2>/dev/null
mkdir /tmp/TMP_RELEASE
pushd /tmp/TMP_RELEASE

rm -rf YaTools-Release YaTools-Debug YaTools-bin Release Debug 2>/dev/null

echo "*********************************************************"
echo "*****************Cloning from GIT URL : *****************"
echo "$GIT_URL"
echo "*****************    INTO DIRECTORY :   *****************"
echo "$PWD"
echo "*********************************************************"
git clone $GIT_URL || exit
cp -r YaTools YaTools-Release
mv YaTools YaTools-Debug

git clone $GIT_URL_BIN || exit

echo "*********************************************************"
echo "********************* Building Release ******************"
echo "*********************************************************"


pushd YaTools-Release/
git checkout ${GIT_REF}
git checkout -b ${GIT_REF}
DESCRIBE=$(git describe)
#rm -rf .git .gitignore
cd build
./configure.sh
cd ../out
make -j6

cd ../../
mkdir Release
cd Release
cp -r ../YaTools-bin/.git ./
git checkout master
git rm -r *

FROM=../YaTools-Release
cp -r ${FROM}/YaCo ./
cp -r ${FROM}/bin/yaco_x86 ./bin
mkdir libs
cp -r ${FROM}/deps/async-0.6.1 ./libs/async
cp -r ${FROM}/deps/pympler ./libs/
git add .
git commit -m "${YATOOLS_VERSION} release update $DESCRIBE"
git push


popd

echo "*********************************************************"
echo "********************* Building Debug ******************"
echo "*********************************************************"


pushd YaTools-Debug/
git checkout ${GIT_REF}
git checkout -b ${GIT_REF}
#rm -rf .git .gitignore
cd build
export CONFIG=Debug
export CMAKE_C_FLAGS=-D_DEBUG
export CMAKE_CXX_FLAGS=-D_DEBUG
./configure.sh
cd ..
sed -i -e "s/DEBUG_REPO=False/DEBUG_REPO=True/" YaCo/repository.py
sed -i -e "s/VALIDATE_EXPORTER_VISITOR=False/VALIDATE_EXPORTER_VISITOR=True/" YaCo/YaCo.py
sed -i -e "s/VALIDATE_EXPORTED_XML=False/VALIDATE_EXPORTED_XML=True/" YaCo/hooks.py

cd out
make -j6

cd ../../
mkdir Debug
cd Debug
cp -r ../YaTools-bin/.git ./
git checkout debug
git rm -r *
FROM=../YaTools-Debug
cp -r ${FROM}/YaCo ./
cp -r ${FROM}/bin/yaco_d_x86 ./bin
mkdir libs
cp -r ${FROM}/deps/async-0.6.1 ./libs/async
cp -r ${FROM}/deps/pympler ./libs/

git add .
git commit -m "${YATOOLS_VERSION} debug update $DESCRIBE"
git push


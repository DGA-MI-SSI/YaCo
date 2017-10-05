#   Copyright (C) 2017 The YaCo Authors
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

#!/bin/bash
BIN_DIR=../bin/yaco_x64/YaTools/bin
OUT_DIR=../out
IDAQ=ida64
PREFIX=ya
EXT=\.i64

echo BIN_DIR=$BIN_DIR
echo OUT_DIR=$OUT_DIR
echo IDAQ=$IDAQ
echo EXT=$EXT

REPO_DIR=$1
if [ -z "$REPO_DIR" ]
then
    CMD="python run_tests.py $BIN_DIR ${PREFIX}init $OUT_DIR $IDAQ"
    echo $CMD
    REPO_DIR=$($CMD | grep repo_ | sed 's/.\+\(repo_.\+\)/\1/g')
    echo bash yatest.sh $REPO_DIR
    exit 0
fi

# get first commit sha1
pushd $OUT_DIR/$REPO_DIR > /dev/null
FIRST_COMMIT=$(git rev-list --max-parents=0 HEAD | tail -n 1)

# sanity checks before calling git clean & git reset...
CHECK_COMMIT=$(git log $FIRST_COMMIT --pretty=oneline)
EXPECTED="$FIRST_COMMIT Initial commit"
if [ "$CHECK_COMMIT" != "$EXPECTED" ]
then
    echo "$CHECK_COMMIT != $EXPECTED"
    exit 1
fi
CHECK_FILE=$(git log $FIRST_COMMIT --oneline --name-only | grep $EXT | sed "s/.\+$EXT/$EXT/g")
if [ "$CHECK_FILE" != "$EXT" ]
then
    echo "$CHECK_FILE != $EXT"
    exit 1
fi

# reset repo
git reset --hard $FIRST_COMMIT
git clean -xdf

# add back local_.i64
REPO_IDB=$(ls *$EXT)
LOCAL_IDB=$(ls *$EXT | sed "s/$EXT/_local$EXT/g")
cp $REPO_IDB $LOCAL_IDB
popd > /dev/null

# run yatest and yacheck tests
python run_tests.py $BIN_DIR "${PREFIX}test|${PREFIX}check" $OUT_DIR $IDAQ $REPO_DIR

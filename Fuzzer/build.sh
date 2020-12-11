#!/bin/bash
LIBFUZZER_SRC_DIR=$(dirname $0)
CXX="${CXX:-clang}"
ROOT_DIR="/home/pany/tls-diff-testing/tls-diff-testing"

for f in $LIBFUZZER_SRC_DIR/*.cpp; do
  if [ $f == "./FuzzerLoop.cpp" ]
  then
    echo "$CXX -I$ROOT_DIR/bitman/inc -I$ROOT_DIR/cryptoman/inc -I$ROOT_DIR/middleman/inc -I$ROOT_DIR/../ -g -O2 -fno-omit-frame-pointer -std=c++11 $f -c &"
    $CXX -I$ROOT_DIR/bitman/inc -I$ROOT_DIR/cryptoman/inc -I$ROOT_DIR/middleman/inc -I$ROOT_DIR/../ -g -O0 -fno-omit-frame-pointer -std=c++11 $f -c &
  else
    $CXX -g -O0 -fno-omit-frame-pointer -std=c++11 $f -c &
  fi
done
wait
rm -f libFuzzer.a
ar ru libFuzzer.a Fuzzer*.o
rm -f Fuzzer*.o


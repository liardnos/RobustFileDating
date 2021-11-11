#!/bin/bash
echo "============= BUILD =============="
rm -rf build
mkdir build && cd build && conan install .. --build=missing --profile ../conanprofile.txt && cmake .. -G "Unix Makefiles" && cmake .
echo "============= COMPILATION =============="
make -j 8 && cd ..
echo "============= RUN =============="

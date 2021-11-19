mkdir build
cd build
conan install .. --build=missing --profile ../conanprofile_win.txt
cmake ..
cmake --build .
cd ..
copy .\build\bin\robustFileDating.exe .

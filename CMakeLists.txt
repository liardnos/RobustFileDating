cmake_minimum_required(VERSION 3.5)
project(robustFileDating)

set(CMAKE_CXX_STANDARD 17)

if (UNIX)
    set(CMAKE_CXX_FLAGS "-Og -Wl,--export-dynamic")
endif()

# Adding extra compilation flags for UNIX

if (UNIX)
    add_compile_options(-Wall -Wextra)
endif()

set(EXECUTABLE_OUTPUT_PATH ..)

if (UNIX)
    SET(CMAKE_BUILD_TYPE DEBUG)
    # file(COPY ${CMAKE_SOURCE_DIR}/conanUNIX DESTINATION ${CMAKE_SOURCE_DIR}/conanfile.txt )
endif()
if (WIN32)
    SET(CMAKE_BUILD_TYPE RELEASE)
    # file(COPY ${CMAKE_SOURCE_DIR}/conanWIN DESTINATION ${CMAKE_SOURCE_DIR}/conanfile.txt )
endif()

#Conan
if (UNIX)
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
endif()
if (WIN32)
    include(${CMAKE_SOURCE_DIR}/build/conanbuildinfo.cmake)
endif()

conan_basic_setup(TARGETS)
if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/master/conan.cmake"
                  "${CMAKE_BINARY_DIR}/conan.cmake")
    include(${CMAKE_BINARY_DIR}/conan.cmake)
endif()

#Sources
file(GLOB_RECURSE SRC_CLI RELATIVE 
    ${CMAKE_SOURCE_DIR} "src/*.cpp"
)

link_directories(${CONAN_LIB_DIRS} ${CONAN_BIN_DIRS})


#Client
add_executable(robustFileDating
${SRC_CLI})

target_link_libraries(robustFileDating
    ${CONAN_LIBS}
)
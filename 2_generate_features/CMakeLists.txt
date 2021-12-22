cmake_minimum_required(VERSION 2.6)
project(1dcnnStatistic)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

include_directories(${CONAN_INCLUDE_DIRS})
message(STATUS ${CONAN_INCLUDE_DIRS})
add_subdirectory(src)

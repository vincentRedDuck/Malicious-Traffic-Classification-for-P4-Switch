set(CMAKE_CXX_FLAGS "-std=c++17")
FILE(GLOB project_sources *.cpp)

add_executable(cnn1d_statistic ${project_sources})
target_link_libraries(cnn1d_statistic ${CONAN_LIBS})
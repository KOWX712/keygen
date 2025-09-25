cmake_minimum_required(VERSION 3.30.5)

project(keygen)

set(CMAKE_LINK_DEPENDS_USE_LINKER OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Os -flto -fvisibility=hidden -ffunction-sections -fdata-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s -flto -Wl,--gc-sections")

link_directories(${CMAKE_SOURCE_DIR}/out/lib)
include_directories(${CMAKE_SOURCE_DIR}/out/include)

add_executable(keygen keygen.cpp)

target_link_libraries(keygen -Wl,-Bstatic ssl crypto -Wl,-Bdynamic -ldl)

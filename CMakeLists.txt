cmake_minimum_required(VERSION 3.5.0)
project(Blowfish VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

enable_testing()

add_library(Blowfish_lib "src/Blowfish.cpp" "src/initValues.cpp" "inc/initValues.h")
target_include_directories(Blowfish_lib PRIVATE "inc")

add_executable(Blowfish_test "src/main.cpp" )
target_include_directories(Blowfish_test PRIVATE "inc")

target_link_libraries(Blowfish_test PRIVATE Blowfish_lib)

add_test(NAME test1 COMMAND $<TARGET_FILE:Blowfish_test>)
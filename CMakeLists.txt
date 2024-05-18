cmake_minimum_required(VERSION 3.5.0)
project(Blowfish VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

add_executable(Blowfish "src/Blowfish.cpp" "src/main.cpp"  "src/initValues.cpp" "inc/initValues.h")
target_include_directories(Blowfish PRIVATE "inc")

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

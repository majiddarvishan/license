cmake_minimum_required(VERSION 3.6)

project(licence
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#mshadow: check
set(CMAKE_INSTALL_COMPONENT "specified")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_BUILD_TYPE "Debug")

add_subdirectory(rsa)
add_subdirectory(hmac)
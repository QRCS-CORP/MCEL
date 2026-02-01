cmake_minimum_required(VERSION 3.15)

project(MCEL_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# MCEL Static Library
file(GLOB_RECURSE MCEL_SOURCES "Source/MCEL/*.c")
file(GLOB_RECURSE MCEL_HEADERS "Source/MCEL/include/*.h")

add_library(mcel STATIC ${MCEL_SOURCES} ${MCEL_HEADERS})
target_include_directories(mcel PUBLIC "Source/MCEL")
target_link_libraries(mcel PUBLIC qsc)

# MCEL Test
file(GLOB_RECURSE MCEL_TEST_SOURCES "Source/MCELTest/*.c")

add_executable(mcel_test ${MCEL_TEST_SOURCES})
target_include_directories(mcel_test PRIVATE "Source/MCELTest")
target_link_libraries(mcel_test PRIVATE mcel)

# Warnings
foreach(target mcel mcel_test)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()

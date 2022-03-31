cmake_minimum_required(VERSION 3.20)
set(LIB_NAME "slowstacktrace")
project(${LIB_NAME} C CXX)

set(SRC_FILES_LIB 
  slowstacktrace.cpp
  slowstacktrace.h
)

set(SRC_FILES_LLVM_UNWIND_SYMBOLIZE
  llvm_printf.cpp
  llvm_stacktrace.cpp
  llvm_unwind_win.cpp
  llvm_unwind_backtrace.cpp
  llvm_symbolizer.cpp
  llvm_symbolizer_posix.cpp
  llvm_symbolizer_win.cpp
  llvm_string.h
  llvm_stacktrace_defs.h
  llvm_stacktrace.h
  llvm_symbolizer_internal.h
)

add_library(${LIB_NAME} ${SRC_FILES_LLVM_UNWIND_SYMBOLIZE} ${SRC_FILES_LIB})


target_compile_options(${LIB_NAME} PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
target_compile_options(${LIB_NAME} PRIVATE -fomit-frame-pointer -fno-stack-protector -fno-rtti -fno-exceptions)

if(UNIX)
  target_link_libraries(${LIB_NAME} PUBLIC pthread ${CMAKE_DL_LIBS})
endif()

add_executable(test-cxx-${LIB_NAME} test-cxx.cpp slowstacktrace.h)
target_link_libraries(test-cxx-${LIB_NAME} PRIVATE ${LIB_NAME})
add_executable(test-c-${LIB_NAME} test-c.c slowstacktrace.h)
target_link_libraries(test-c-${LIB_NAME} PRIVATE ${LIB_NAME})
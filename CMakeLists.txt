cmake_minimum_required(VERSION 3.20)
set(LIB_NAME "slowstacktrace")
project(${LIB_NAME} C CXX)

set(SRC_FILES_LIB 
  slowstacktrace.cpp
)

set(SRC_FILES_LLVM_UNWIND_SYMBOLIZE
  llvm_printf.cpp
  llvm_stacktrace.cpp
  llvm_unwind_win.cpp
  llvm_unwind_backtrace.cpp
  llvm_symbolizer.cpp
  llvm_symbolizer_posix.cpp
  llvm_symbolizer_win.cpp
)

add_library(${LIB_NAME})
target_sources(${LIB_NAME} PRIVATE ${SRC_FILES_LLVM_UNWIND_SYMBOLIZE} ${SRC_FILES_LIB})
target_sources(${LIB_NAME} INTERFACE slowstacktrace.h)
target_include_directories(${LIB_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(${LIB_NAME} PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
target_compile_options(${LIB_NAME} PRIVATE -fomit-frame-pointer -fno-stack-protector -fno-rtti -fno-exceptions)

if(UNIX)
  target_link_libraries(${LIB_NAME} PUBLIC pthread ${CMAKE_DL_LIBS})
endif()

add_executable(test-cxx-${LIB_NAME} test-cxx.cpp slowstacktrace.h)
target_link_libraries(test-cxx-${LIB_NAME} PRIVATE ${LIB_NAME})
add_executable(test-c-${LIB_NAME} test-c.c slowstacktrace.h)
target_link_libraries(test-c-${LIB_NAME} PRIVATE ${LIB_NAME})


include(GNUInstallDirs)
install(TARGETS ${LIB_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(
  FILES "slowstacktrace.h"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
      
# install(FILES slowstacktrace.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

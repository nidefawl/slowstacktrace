// (c) Michael Hept 2020

#include "llvm_stacktrace.h"
#include "libslowstacktrace.h"
#include <stddef.h>

// Render the contents of "info" structure, which represents the contents of
// stack frame "frame_no" and appends it to the "buffer". "format" is a
// string with placeholders, which is copied to the output with
// placeholders substituted with the contents of "info". For example,
// format string
//   "  frame %n: function %F at %S"
// will be turned into
//   "  frame 10: function foo::bar() at my/file.cc:10"
// You may additionally pass "strip_path_prefix" to strip prefixes of paths to
// source files and modules, and "strip_func_prefix" to strip prefixes of
// function names.
// Here's the full list of available placeholders:
//   %% - represents a '%' character;
//   %n - frame number (copy of frame_no);
//   %p - PC in hex format;
//   %m - path to module (binary or shared object);
//   %o - offset in the module in hex format;
//   %f - function name;
//   %q - offset in the function in hex format (*if available*);
//   %s - path to source file;
//   %l - line in the source file;
//   %c - column in the source file;
//   %F - if function is known to be <foo>, prints "in <foo>", possibly
//        followed by the offset in this function, but only if source file
//        is unknown;
//   %S - prints file/line/column information;
//   %L - prints location information: file/line/column, if it is known, or
//        module+offset if it is known, or (<unknown module>) string.
//   %M - prints module basename and offset, if it is known, or PC.
// static const char kDefaultFormat[] = "    #%n %p %F %L";

extern "C" {

void get_thread_stacktrace(char *out_buf, std::size_t out_buf_size) {
  using namespace llvm_stacktrace;
  const auto pc = StackTrace::GetCurrentPc();
  const auto frame = GET_CURRENT_FRAME();
  BufferedStackTrace stack;
  stack.Unwind(pc, frame, kStackTraceMax);
  if (out_buf && out_buf_size) {
    stack.PrintTo(out_buf, out_buf_size);
  } else {
    stack.Print();
  }
}

void print_thread_stacktrace() {
  get_thread_stacktrace(nullptr, 0);
}

}
// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#pragma once
#include "llvm_stacktrace_defs.h"
#include <vector>

namespace llvm_stacktrace {

const char *StripModuleName(const char *module);
int snprintf(char *buffer, uptr length, const char *format, ...) FORMAT(3, 4);
void Printf(const char *format, ...) FORMAT(1, 2);
void Report(const char *format, ...) FORMAT(1, 2);
void RawWrite(const char *str);

#define VReport(level, ...)                                              \
  do {                                                                   \
    /* if ((uptr)Verbosity() >= (level)) */ Report(__VA_ARGS__); \
  } while (0)
#define VPrintf(level, ...)                                              \
  do {                                                                   \
    /* if ((uptr)Verbosity() >= (level)) */ Printf(__VA_ARGS__); \
  } while (0)


class InternalScopedString {
 public:
  InternalScopedString() : buffer_(1) { buffer_[0] = '\0'; }

  uptr length() const { return buffer_.size() - 1; }
  void clear() {
    buffer_.resize(1);
    buffer_[0] = '\0';
  }
  void append(const char *format, ...) FORMAT(2, 3);
  void set(const char *str);
  const char *data() const { return buffer_.data(); }
  char *data() { return buffer_.data(); }

 private:
  std::vector<char> buffer_;
};

}  // namespace llvm_stacktrace

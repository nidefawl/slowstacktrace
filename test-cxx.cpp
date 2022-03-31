// (c) Michael Hept 2022. See LICENSE.txt

#include "slowstacktrace.h"
#include <cstdio>

extern "C" void get_thread_stacktrace(char *out_buf, std::size_t out_buf_size);

void logStackTrace() {
  char buf[1024*8]{};
  get_thread_stacktrace(buf, sizeof(buf));
  std::puts(buf);
}

template<int A> int recursiveCall(int maxDepth, int depth = 0) {
  if (depth >= maxDepth)
  {
      logStackTrace();
      return maxDepth;
  }
  depth++;
  switch (depth%4) {
    case 0: return recursiveCall<0>(maxDepth, depth);
    case 1: return recursiveCall<1>(maxDepth, depth);
    case 2: return recursiveCall<2>(maxDepth, depth);
    case 3: return recursiveCall<3>(maxDepth, depth);
  }
  while(1);
}

int main() {
  std::puts("test begin\n");
  logStackTrace();
  recursiveCall<0>(16);
  std::puts("test end\n");
  return 0;
}
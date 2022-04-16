// (c) Michael Hept 2022. See LICENSE.txt

#include "slowstacktrace.h"
#include <cstdio>

template <int A> int recursiveCall(int maxDepth, int depth = 0) {
  if (depth >= maxDepth) {
    print_thread_stacktrace("%m %o");
    print_thread_stacktrace("    #%n %p %F %L");
    return maxDepth;
  }
  depth++;
  switch (depth % 4) {
  case 0:
    return recursiveCall<0>(maxDepth, depth);
  case 1:
    return recursiveCall<1>(maxDepth, depth);
  case 2:
    return recursiveCall<2>(maxDepth, depth);
  case 3:
    return recursiveCall<3>(maxDepth, depth);
  }
  while (1);
}

int main() {
  std::puts("test begin\n");
  print_thread_stacktrace("%b %n %p %m %o %f %q %s");
  print_thread_stacktrace("%l %c %F %S %l %M");

  char buf[1024 * 8]{};
  get_thread_stacktrace(buf, sizeof(buf), "    #%n %p %F %L");
  std::puts(buf);

  recursiveCall<0>(32);
  std::puts("test end\n");
  return 0;
}
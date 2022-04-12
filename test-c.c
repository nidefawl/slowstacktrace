// (c) Michael Hept 2022. See LICENSE.txt
#include "slowstacktrace.h"
#include <stdio.h>

void logStackTrace() {
  char buf[4096] = { 0 };
  get_thread_stacktrace(buf, sizeof(buf));
  puts(buf);
}

int main() {
  puts("test begin\n");
  logStackTrace();
  puts("test end\n");
  return 0;
}
// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#pragma once

#include "llvm_stacktrace.h"
#include "llvm_symbolizer.h"
#include "llvm_string.h"

namespace llvm_stacktrace {

const char *DemangleSwiftAndCXX(const char *name);

// SymbolizerTool is an interface that is implemented by individual "tools"
// that can perform symbolication (external llvm-symbolizer, libbacktrace,
// Windows DbgHelp symbolizer, etc.).
class SymbolizerTool {
 public:
  // The main |Symbolizer| class implements a "fallback chain" of symbolizer
  // tools. In a request to symbolize an address, if one tool returns false,
  // the next tool in the chain will be tried.
  SymbolizerTool *next;

  SymbolizerTool() : next(nullptr) { }

  // Can't declare pure virtual functions in sanitizer runtimes:
  // __cxa_pure_virtual might be unavailable.

  // The |stack| parameter is inout. It is pre-filled with the address,
  // module base and module offset values and is to be used to construct
  // other stack frames.
  virtual bool SymbolizePC(uptr addr, SymbolizedStack *stack) {
    UNIMPLEMENTED();
  }

  // The |info| parameter is inout. It is pre-filled with the module base
  // and module offset values.
  virtual bool SymbolizeData(uptr addr, DataInfo *info) {
    UNIMPLEMENTED();
  }

  virtual bool SymbolizeFrame(uptr addr, FrameInfo *info) {
    return false;
  }

 protected:
  ~SymbolizerTool() {}
};

// SymbolizerProcess encapsulates communication between the tool and
// external symbolizer program, running in a different subprocess.
// SymbolizerProcess may not be used from two threads simultaneously.
class SymbolizerProcess {
 public:
  explicit SymbolizerProcess(const char *path, bool use_posix_spawn = false);
  const char *SendCommand(const char *command);

 protected:
  ~SymbolizerProcess() {}

  /// The maximum number of arguments required to invoke a tool process.
  static const unsigned kArgVMax = 16;

  // Customizable by subclasses.
  virtual bool StartSymbolizerSubprocess();
  virtual bool ReadFromSymbolizer(char *buffer, uptr max_length);
  // Return the environment to run the symbolizer in.
  virtual char **GetEnvP() { return GetEnviron(); }

 private:
  virtual bool ReachedEndOfOutput(const char *buffer, uptr length) const {
    UNIMPLEMENTED();
  }

  /// Fill in an argv array to invoke the child process.
  virtual bool GetArgV(const char *path_to_binary,
                       const char *(&argv)[kArgVMax]) const {
    UNIMPLEMENTED();
  }

  bool Restart();
  const char *SendCommandImpl(const char *command);
  bool WriteToSymbolizer(const char *buffer, uptr length);

  const char *path_;
  fd_t input_fd_;
  fd_t output_fd_;

  static const uptr kBufferSize = 16 * 1024;
  char buffer_[kBufferSize];

  static const uptr kMaxTimesRestarted = 5;
  static const int kSymbolizerStartupTimeMillis = 10;
  uptr times_restarted_;
  bool failed_to_start_;
  bool reported_invalid_path_;
  bool use_posix_spawn_;
};

class LLVMSymbolizerProcess;

// This tool invokes llvm-symbolizer in a subprocess. It should be as portable
// as the llvm-symbolizer tool is.
class LLVMSymbolizer final : public SymbolizerTool {
 public:
  explicit LLVMSymbolizer(const char *path);

  bool SymbolizePC(uptr addr, SymbolizedStack *stack) override;
  bool SymbolizeData(uptr addr, DataInfo *info) override;
  bool SymbolizeFrame(uptr addr, FrameInfo *info) override;

 private:
  const char *FormatAndSendCommand(const char *command_prefix,
                                   const char *module_name, uptr module_offset,
                                   ModuleArch arch);

  LLVMSymbolizerProcess *symbolizer_process_;
  static const uptr kBufferSize = 16 * 1024;
  char buffer_[kBufferSize];
};

// Parses one or more two-line strings in the following format:
//   <function_name>
//   <file_name>:<line_number>[:<column_number>]
// Used by LLVMSymbolizer, Addr2LinePool and InternalSymbolizer, since all of
// them use the same output format.  Returns true if any useful debug
// information was found.
void ParseSymbolizePCOutput(const char *str, SymbolizedStack *res);

// Parses a two-line string in the following format:
//   <symbol_name>
//   <start_address> <size>
// Used by LLVMSymbolizer and InternalSymbolizer.
void ParseSymbolizeDataOutput(const char *str, DataInfo *info);

// I/O
// Define these as macros so we can use them in linker initialized global
// structs without dynamic initialization.
#define kInvalidFd ((fd_t)-1)
#define kStdinFd ((fd_t)0)
#define kStdoutFd ((fd_t)1)
#define kStderrFd ((fd_t)2)

void CloseFile(fd_t fd);
bool ReadFromFile(fd_t fd, void *buff, uptr buff_size, uptr *bytes_read, error_t *error_p);
bool WriteToFile(fd_t fd, const void *buff, uptr buff_size, uptr *bytes_written, error_t *error_p);
bool FileExists(const char *filename);
bool DirExists(const char *path);
char *FindPathToBinary(const char *name);

}  // namespace llvm_stacktrace


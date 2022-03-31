// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#pragma once

#include "llvm_stacktrace_defs.h"
#include <cstring>
#include <vector>

namespace llvm_stacktrace {

enum ModuleArch {
  kModuleArchUnknown,
  kModuleArchI386,
  kModuleArchX86_64,
  kModuleArchX86_64H,
  kModuleArchARMV6,
  kModuleArchARMV7,
  kModuleArchARMV7S,
  kModuleArchARMV7K,
  kModuleArchARM64,
  kModuleArchRISCV64,
  kModuleArchHexagon
};

// When adding a new architecture, don't forget to also update
// script/asan_symbolize.py and sanitizer_symbolizer_libcdep.cpp.
inline const char *ModuleArchToString(ModuleArch arch) {
  switch (arch) {
    case kModuleArchUnknown:
      return "";
    case kModuleArchI386:
      return "i386";
    case kModuleArchX86_64:
      return "x86_64";
    case kModuleArchX86_64H:
      return "x86_64h";
    case kModuleArchARMV6:
      return "armv6";
    case kModuleArchARMV7:
      return "armv7";
    case kModuleArchARMV7S:
      return "armv7s";
    case kModuleArchARMV7K:
      return "armv7k";
    case kModuleArchARM64:
      return "arm64";
    case kModuleArchRISCV64:
      return "riscv64";
    case kModuleArchHexagon:
      return "hexagon";
  }
  CHECK(0 && "Invalid module arch");
  return "";
}

const uptr kModuleUUIDSize = 32;
const uptr kMaxSegName = 16;

// Represents a binary loaded into virtual memory (e.g. this can be an
// executable or a shared object).
class LoadedModule {
 public:
  LoadedModule()
      : full_name_(nullptr),
        base_address_(0),
        max_executable_address_(0),
        arch_(kModuleArchUnknown),
        uuid_size_(0),
        instrumented_(false) {
    std::memset(uuid_, 0, kModuleUUIDSize);
    ranges_.clear();
  }
  void set(const char *module_name, uptr base_address);
  void set(const char *module_name, uptr base_address, ModuleArch arch,
           u8 uuid[kModuleUUIDSize], bool instrumented);
  void setUuid(const char *uuid, uptr size);
  void clear();
  void addAddressRange(uptr beg, uptr end, bool executable, bool writable,
                       const char *name = nullptr);
  bool containsAddress(uptr address) const;

  const char *full_name() const { return full_name_; }
  uptr base_address() const { return base_address_; }
  uptr max_executable_address() const { return max_executable_address_; }
  ModuleArch arch() const { return arch_; }
  const u8 *uuid() const { return uuid_; }
  uptr uuid_size() const { return uuid_size_; }
  bool instrumented() const { return instrumented_; }

  struct AddressRange {
    AddressRange *next;
    uptr beg;
    uptr end;
    bool executable;
    bool writable;
    char name[kMaxSegName];

    AddressRange(uptr beg, uptr end, bool executable, bool writable,
                 const char *name)
        : next(nullptr),
          beg(beg),
          end(end),
          executable(executable),
          writable(writable) {
      std::strncpy(this->name, (name ? name : ""), ARRAY_SIZE(this->name));
    }
  };

  const std::vector<AddressRange> &ranges() const { return ranges_; }

 private:
  char *full_name_;  // Owned.
  uptr base_address_;
  uptr max_executable_address_;
  ModuleArch arch_;
  uptr uuid_size_;
  u8 uuid_[kModuleUUIDSize];
  bool instrumented_;
  std::vector<AddressRange> ranges_;
};

// List of LoadedModules. OS-dependent implementation is responsible for
// filling this information.
class ListOfModules {
 public:
  ListOfModules() : initialized(false) {}
  ~ListOfModules() { clear(); }
  void init();
  uptr size() const { return modules_.size(); }
  const LoadedModule &operator[](uptr i) const {
    CHECK_LT(i, modules_.size());
    return modules_[i];
  }

  const std::vector<LoadedModule>& getList() const {
    return modules_;
  }

  std::vector<LoadedModule>& getList() {
    return modules_;
  }

 private:
  void clear() {
    for (auto &module : modules_) module.clear();
    modules_.clear();
  }
  void clearOrInit() {
    initialized ? clear() : modules_.reserve(kInitialCapacity);
    initialized = true;
  }

  std::vector<LoadedModule> modules_;
  // We rarely have more than 16K loaded modules.
  static const uptr kInitialCapacity = 1 << 14;
  bool initialized;
};
struct AddressInfo {
  // Owns all the string members. Storage for them is
  // (de)allocated using sanitizer internal allocator.
  uptr address;

  char *module;
  uptr module_offset;
  ModuleArch module_arch;
  u8 uuid[kModuleUUIDSize];
  uptr uuid_size;

  static const uptr kUnknown = ~(uptr)0;
  char *function;
  uptr function_offset;

  char *file;
  int line;
  int column;

  AddressInfo();
  // Deletes all strings and resets all fields.
  void Clear();
  void FillModuleInfo(const char *mod_name, uptr mod_offset, ModuleArch arch);
  void FillModuleInfo(const LoadedModule &mod);
  uptr module_base() const { return address - module_offset; }
};

// Linked list of symbolized frames (each frame is described by AddressInfo).
struct SymbolizedStack {
  SymbolizedStack *next;
  AddressInfo info;
  static SymbolizedStack *New(uptr addr);
  // Deletes current, and all subsequent frames in the linked list.
  // The object cannot be accessed after the call to this function.
  void ClearAll();

 private:
  SymbolizedStack();
};

// For now, DataInfo is used to describe global variable.
struct DataInfo {
  // Owns all the string members. Storage for them is
  // (de)allocated using sanitizer internal allocator.
  char *module;
  uptr module_offset;
  ModuleArch module_arch;

  char *file;
  uptr line;
  char *name;
  uptr start;
  uptr size;

  DataInfo();
  void Clear();
};

struct LocalInfo {
  char *function_name = nullptr;
  char *name = nullptr;
  char *decl_file = nullptr;
  unsigned decl_line = 0;

  bool has_frame_offset = false;
  bool has_size = false;
  bool has_tag_offset = false;

  sptr frame_offset;
  uptr size;
  uptr tag_offset;

  void Clear();
};

struct FrameInfo {
  char *module;
  uptr module_offset;
  ModuleArch module_arch;

  std::vector<LocalInfo> locals;
  void Clear();
};

class SymbolizerTool;

class Symbolizer final {
 public:
  explicit Symbolizer(std::vector<SymbolizerTool*> tools);
  ~Symbolizer();
  /// Initialize and return platform-specific implementation of symbolizer
  /// (if it wasn't already initialized).
  static Symbolizer *GetOrInit();
  static void LateInitialize();
  // Returns a list of symbolized frames for a given address (containing
  // all inlined functions, if necessary).
  SymbolizedStack *SymbolizePC(uptr address);
  bool SymbolizeData(uptr address, DataInfo *info);
  bool SymbolizeFrame(uptr address, FrameInfo *info);

  const LoadedModule *FindModuleForAddress(uptr address);

  void InvalidateModuleList();

 private:
  /// Platform-specific function for creating a Symbolizer object.
  static Symbolizer *PlatformInit();

  bool FindModuleNameAndOffsetForAddress(uptr address, const char **module_name,
                                         uptr *module_offset,
                                         ModuleArch *module_arch);
  ListOfModules modules_;

  static Symbolizer *symbolizer_;

  std::vector<SymbolizerTool*> tools_;

};

#ifdef SANITIZER_WINDOWS
void InitializeDbgHelpIfNeeded();
#endif

}  // namespace __sanitizer

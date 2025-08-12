#pragma once

#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
// RLBox allows applications to provide a custom shared lock implementation
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  include <shared_mutex>
#endif
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <unistd.h>

#include "lfi_arch.h"
#include "lfi_linux.h"

#include "lfi_sepstack_invoker.hpp"

// Pull the helper header from the main repo for dynamic_check and scope_exit
#include "rlbox_helpers.hpp"

#define RLBOX_LFI_UNUSED(...) (void)__VA_ARGS__

// Use the same convention as rlbox to allow applications to customize the
// shared lock
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  define RLBOX_SHARED_LOCK(name) std::shared_timed_mutex name
#  define RLBOX_ACQUIRE_SHARED_GUARD(name, ...)                                \
    std::shared_lock<std::shared_timed_mutex> name(__VA_ARGS__)
#  define RLBOX_ACQUIRE_UNIQUE_GUARD(name, ...)                                \
    std::unique_lock<std::shared_timed_mutex> name(__VA_ARGS__)
#else
#  if !defined(RLBOX_SHARED_LOCK) || !defined(RLBOX_ACQUIRE_SHARED_GUARD) ||   \
    !defined(RLBOX_ACQUIRE_UNIQUE_GUARD)
#    error                                                                     \
      "RLBOX_USE_CUSTOM_SHARED_LOCK defined but missing definitions for RLBOX_SHARED_LOCK, RLBOX_ACQUIRE_SHARED_GUARD, RLBOX_ACQUIRE_UNIQUE_GUARD"
#  endif
#endif

namespace rlbox {

namespace detail {
  // relying on the dynamic check settings (exception vs abort) in the rlbox lib
  inline void dynamic_check(bool check, const char* const msg);
}

namespace lfi_detail {

  template<typename T>
  constexpr bool false_v = false;

  // https://stackoverflow.com/questions/6512019/can-we-get-the-type-of-a-lambda-argument
  namespace return_argument_detail {
    template<typename Ret, typename... Rest>
    Ret helper(Ret (*)(Rest...));

    template<typename Ret, typename F, typename... Rest>
    Ret helper(Ret (F::*)(Rest...));

    template<typename Ret, typename F, typename... Rest>
    Ret helper(Ret (F::*)(Rest...) const);

    template<typename F>
    decltype(helper(&F::operator())) helper(F);
  } // namespace return_argument_detail

  template<typename T>
  using return_argument =
    decltype(return_argument_detail::helper(std::declval<T>()));

  ///////////////////////////////////////////////////////////////

  // https://stackoverflow.com/questions/37602057/why-isnt-a-for-loop-a-compile-time-expression
  namespace compile_time_for_detail {
    template<std::size_t N>
    struct num
    {
      static const constexpr auto value = N;
    };

    template<class F, std::size_t... Is>
    inline void compile_time_for_helper(F func, std::index_sequence<Is...>)
    {
      (func(num<Is>{}), ...);
    }
  } // namespace compile_time_for_detail

  template<std::size_t N, typename F>
  inline void compile_time_for(F func)
  {
    compile_time_for_detail::compile_time_for_helper(
      func, std::make_index_sequence<N>());
  }

} // namespace lfi_detail


class rlbox_lfi_sandbox;

struct rlbox_lfi_sandbox_thread_data
{
  rlbox_lfi_sandbox* sandbox;
  uint32_t last_callback_invoked;
};

#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES

rlbox_lfi_sandbox_thread_data* get_rlbox_lfi_sandbox_thread_data();
#  define RLBOX_LFI_SANDBOX_STATIC_VARIABLES()                                \
    thread_local rlbox::rlbox_lfi_sandbox_thread_data                         \
      rlbox_lfi_sandbox_thread_info{ 0, 0 };                                  \
    namespace rlbox {                                                          \
      rlbox_lfi_sandbox_thread_data* get_rlbox_lfi_sandbox_thread_data()     \
      {                                                                        \
        return &rlbox_lfi_sandbox_thread_info;                                \
      }                                                                        \
    }                                                                          \
    static_assert(true, "Enforce semi-colon")

#endif

struct rlbox_lfi_callback_info
{
  // Callbacks are registered and unregistered using a unique key
  void* unique_key;
  // The host callback function to invoke (This is an RLBox function that fixes
  // ABI before invoking the real host callback).
  void* callback;
  // The stub in the sandboxed library that is called when the library invokes a
  // particular callback
  void* sandbox_stub;
  // The pointer to the rlbox_lfi_sandbox interceptor function that intercepts
  // this callback
  void* interceptor_assignment;
};

class rlbox_lfi_sandbox
{
public:
  using T_LongLongType = long long;
  using T_LongType = long;
  using T_IntType = int;
  using T_PointerType = uintptr_t;
  using T_ShortType = short;

private:
  struct LFIEngine* mLFIEngine {0};
  struct LFILinuxEngine * mLFILinuxEngine {0};
  struct LFILinuxProc * mLFILinuxProc {0};
  struct LFILinuxThread * mLFIMainThread {0};
  struct LFIContext ** mLFIMainThreadCtx {0};

  struct LFIBox * mLFIBox {0};
  bool instance_initialized = false;
  uintptr_t heap_base = 0;
  size_t heap_size = 0;
  void* mLFIRetFn = 0;
  size_t return_slot_size = 0;
  T_PointerType return_slot = 0;
  static constexpr size_t mStackSize = 2 * 1024 * 1024;

  RLBOX_SHARED_LOCK(mThreadContextMapLock);
  // A map that maintains the context structure for each host thread that has invoked a sandbox function
  std::map<uintptr_t, struct LFIContext *> mThreadContextMap;

  static constexpr size_t MAX_CALLBACKS = 128;

  mutable RLBOX_SHARED_LOCK(callback_mutex);
  // Info about registered callbacks
  rlbox_lfi_callback_info callback_info[MAX_CALLBACKS]{0};
  // Mapping between the "stub in the sandboxed library" that is invoked during
  // a callback and the host callback (This is an RLBox function that fixes ABI
  // before invoking the real host callback)
  mutable std::map<void*, const void*> callback_stub_hostfunc_map;

#ifndef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
  thread_local static inline rlbox_lfi_sandbox_thread_data thread_data{ 0, 0 };
#endif

  // we use the address of a thread_local variable as a cheap thread identifier
  static inline uintptr_t get_cheap_thread_id() {
#ifndef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    return reinterpret_cast<uintptr_t>(&thread_data);
#else
    return  reinterpret_cast<uintptr_t>(get_rlbox_lfi_sandbox_thread_data());
#endif
  }

  LFIContext** get_fresh_or_existing_thread_ctx() {
    // Check if this thread has already been initialized and return that context if it exists
    uintptr_t cheap_thread_id = get_cheap_thread_id();
    {
      RLBOX_ACQUIRE_SHARED_GUARD(lock, mThreadContextMapLock);
      auto iter = mThreadContextMap.find(cheap_thread_id);
      if (iter != mThreadContextMap.end()) {
        // thread has already been initialized. Return that context
        auto ret = &(iter->second);
        return ret;
      }
    }

    // Initializing this thread for the first time.
    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, mThreadContextMapLock);
    const auto iter_and_status = mThreadContextMap.insert({ cheap_thread_id, nullptr });
    auto iter = iter_and_status.first;
    auto ret = &(iter->second);
    // initialize the context
    lfi_clone(mLFIBox, ret);
    return ret;
  }

template<uint32_t N, typename T_Ret, typename... T_Args>
static void callback_interceptor()
{
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
  auto& thread_data = *get_rlbox_lfi_sandbox_thread_data();
#endif
  thread_data.last_callback_invoked = N;
  using T_Func = T_Ret (*)(T_Args...);
  T_Func func;
  {
    RLBOX_ACQUIRE_SHARED_GUARD(lock, thread_data.sandbox->callback_mutex);
    func = reinterpret_cast<T_Func>(thread_data.sandbox->callback_info[N].callback);
  }


#ifndef RLBOX_SINGLE_THREADED_INVOCATIONS
    LFIContext** curr_ctx = thread_data.sandbox->get_fresh_or_existing_thread_ctx();
#else
    LFIContext** curr_ctx = thread_data.sandbox->mLFIMainThreadCtx;
#endif

  invoke_callback_from_separate_stack(lfi_ctx_regs(*curr_ctx),
    thread_data.sandbox->heap_base,
    thread_data.sandbox->heap_base + thread_data.sandbox->heap_size,
    func
  );
}

protected:

#define FALLIBLE_DYNAMIC_CHECK(infallible, cond, msg)                          \
  if (infallible) {                                                            \
    detail::dynamic_check(cond, msg);                                          \
  } else if (!(cond)) {                                                        \
    impl_destroy_sandbox();                                                    \
    return false;                                                              \
  }

  /**
   * @brief creates the LFI sandbox from the given shared library
   *
   * @param infallible if set to true, the sandbox aborts on failure. If false,
   * the sandbox returns creation status as a return value
   * @return true when sandbox is successfully created. false when infallible is
   * set to false and sandbox was not successfully created. If infallible is set
   * to true, this function will never return false.
   */
  inline bool impl_create_sandbox(
    uint8_t* lib_start,
    uint8_t* lib_end,
    bool infallible = true)
  {
    FALLIBLE_DYNAMIC_CHECK(
      infallible, instance_initialized == false, "Sandbox already initialized");

    mLFIEngine = lfi_new(
      (struct LFIOptions) {
        .pagesize = static_cast<size_t>(getpagesize()),
        .boxsize = static_cast<size_t>(4) * 1024 * 1024 * 1024,
        .verbose = false,
        .stores_only = false,
        // we expect that verification is run at build time at this is an AOT use case.
        // Verifying at runtime just adds unnecessary slow downs.
        .no_verify = true,
        .allow_wx = false,
        .no_init_sigaltstack = false,
      },
      1 /* sandbox count */);
    FALLIBLE_DYNAMIC_CHECK(infallible, mLFIEngine, "Error creating LFI engine");

    const char *lfi_dir_maps[] = { NULL };

    mLFILinuxEngine = lfi_linux_new(mLFIEngine,
      (struct LFILinuxOptions) {
          .stacksize = mStackSize,
          .verbose = false,
          .perf = false,
          .dir_maps = lfi_dir_maps,
          .wd = NULL,
          .exit_unknown_syscalls = true,
          .sys_passthrough = false,
          .debug = false,
      });
    FALLIBLE_DYNAMIC_CHECK(infallible, mLFILinuxEngine, "Error creating LFI linux engine");

    mLFILinuxProc = lfi_proc_new(mLFILinuxEngine);
    FALLIBLE_DYNAMIC_CHECK(infallible, mLFILinuxProc, "Error creating LFI linux process");

    bool lfi_proc_loaded = lfi_proc_load(mLFILinuxProc, lib_start, lib_end - lib_start, "rlboxed_library");
    FALLIBLE_DYNAMIC_CHECK(infallible, lfi_proc_loaded, "LFI load process failed");

    mLFIBox = lfi_proc_box(mLFILinuxProc);

    lfi_box_init_ret(mLFIBox);

    const char * lfi_envp[] = { "LFI=1", NULL,};
    const char *lfi_argv[] = { "/rlboxed_library", NULL };
    mLFIMainThread = lfi_thread_new(mLFILinuxProc, 0, lfi_argv, lfi_envp);
    FALLIBLE_DYNAMIC_CHECK(
      infallible, mLFIMainThread, "LFI main thread creation failed");

    int lfi_thread_inited = lfi_thread_run(mLFIMainThread);
    FALLIBLE_DYNAMIC_CHECK(
      infallible, lfi_thread_inited == 0, "LFI main thread init failed");

    mLFIMainThreadCtx = lfi_thread_ctxp(mLFIMainThread);
#ifndef RLBOX_SINGLE_THREADED_INVOCATIONS
    mThreadContextMap[get_cheap_thread_id()] = *mLFIMainThreadCtx;
#endif

    instance_initialized = true;

    heap_base = reinterpret_cast<uintptr_t>(impl_get_memory_location());
    heap_size = impl_get_total_memory();

    // Check that the heap is aligned to the pointer size i.e. 32-bit pointer =>
    // aligned to 4GB. The implementations of
    // impl_get_unsandboxed_pointer_no_ctx and impl_get_sandboxed_pointer_no_ctx
    // below rely on this.
    uintptr_t heap_offset_mask = std::numeric_limits<uint32_t>::max();
    FALLIBLE_DYNAMIC_CHECK(infallible,
                            (heap_base & heap_offset_mask) == 0,
                            "Sandbox heap not aligned to 4GB");

    return true;
  }

  inline void impl_destroy_sandbox()
  {
    if (return_slot_size) {
      impl_free_in_sandbox(return_slot);
    }
    if (instance_initialized) {
      instance_initialized = false;
      if (mLFIMainThread) {
        lfi_thread_free(mLFIMainThread);
        mLFIMainThread = 0;
      }
      if (mLFILinuxProc) {
        lfi_proc_free(mLFILinuxProc);
        mLFILinuxProc = 0;
      }
      if (mLFILinuxEngine) {
        lfi_linux_free(mLFILinuxEngine);
        mLFILinuxEngine = 0;
      }
      if (mLFIEngine) {
        lfi_free(mLFIEngine);
        mLFIEngine = 0;
      }
    }
  }

  void* impl_lookup_symbol(const char* func_name)
  {
    uint64_t symbol = lfi_proc_sym(mLFILinuxProc, func_name);
    detail::dynamic_check(symbol != 0,
                          "LFI Symbol lookup failed!");
    return reinterpret_cast<void*>(symbol);
  }

  template<typename T>
  inline void* impl_get_unsandboxed_pointer(T_PointerType p) const
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
      auto found = callback_stub_hostfunc_map.find(reinterpret_cast<void*>(p));
      if (found != callback_stub_hostfunc_map.end()) {
        auto ret = found->second;
        return const_cast<void*>(ret);
      }
    }

    const uint32_t truncated = static_cast<uint32_t>(p);
    return reinterpret_cast<void*>(heap_base | p);
  }

  template<typename T>
  inline T_PointerType impl_get_sandboxed_pointer(const void* p) const
  {
    return reinterpret_cast<T_PointerType>(p);
  }

  template<typename T>
  static inline void* impl_get_unsandboxed_pointer_no_ctx(
    T_PointerType p,
    const void* example_unsandboxed_ptr,
    rlbox_lfi_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
      // swizzling function pointers needs access to the
      // callback_stub_hostfunc_map and thus cannot be done without context
      auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
      return sandbox->template impl_get_unsandboxed_pointer<T>(p);
    } else {
      // we can assume that the heap is aligned and grab the memory base from the example_unsandboxed_ptr
      uintptr_t offset_mask = std::numeric_limits<uint32_t>::max();
      uintptr_t heap_base_mask = ~offset_mask;
      uintptr_t computed_heap_base = reinterpret_cast<uintptr_t>(example_unsandboxed_ptr) & heap_base_mask;
      uintptr_t computed_offset = p & offset_mask;
      uintptr_t ret = computed_heap_base | computed_offset;
      return reinterpret_cast<void*>(ret);
    }
  }

  template<typename T>
  static inline T_PointerType impl_get_sandboxed_pointer_no_ctx(
    const void* p,
    const void* example_unsandboxed_ptr,
    rlbox_lfi_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    // sandbox representation of the pointer is the same as the host
    RLBOX_LFI_UNUSED(example_unsandboxed_ptr);
    return reinterpret_cast<T_PointerType>(p);
  }

  static inline bool impl_is_in_same_sandbox(const void* p1, const void* p2)
  {
    uintptr_t offset_mask = std::numeric_limits<uint32_t>::max();
    uintptr_t heap_base_mask = ~offset_mask;
    return (reinterpret_cast<uintptr_t>(p1) & heap_base_mask) ==
           (reinterpret_cast<uintptr_t>(p2) & heap_base_mask);
  }

  inline bool impl_is_pointer_in_sandbox_memory(const void* p)
  {
    size_t length = heap_size;
    uintptr_t p_val = reinterpret_cast<uintptr_t>(p);
    return p_val >= heap_base && p_val < (heap_base + length);
  }

  inline bool impl_is_pointer_in_app_memory(const void* p)
  {
    return !(impl_is_pointer_in_sandbox_memory(p));
  }

  inline size_t impl_get_total_memory()
  {
    return lfi_box_info(mLFIBox).size;
  }

  inline void* impl_get_memory_location() const
  {
    return reinterpret_cast<void*>(lfi_box_info(mLFIBox).base);
  }

  template<typename T, typename T_Converted, typename... T_Args>
  auto impl_invoke_with_func_ptr(T_Converted* func_ptr, T_Args&&... params) -> lfi_detail::return_argument<T_Converted*>
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_lfi_sandbox_thread_data();
#endif
    auto old_sandbox = thread_data.sandbox;
    thread_data.sandbox = this;
    auto on_exit =
      detail::make_scope_exit([&] { thread_data.sandbox = old_sandbox; });

#ifndef RLBOX_SINGLE_THREADED_INVOCATIONS
    LFIContext** curr_ctx = get_fresh_or_existing_thread_ctx();
#else
    LFIContext** curr_ctx = mLFIMainThreadCtx;
#endif

    lfi_invoke_info = (struct LFIInvokeInfo) {
        .ctx = curr_ctx,
        .targetfn = reinterpret_cast<uintptr_t>(func_ptr),
        .box = mLFIBox,
    };

    return invoke_func_on_separate_stack<T_Converted>(lfi_ctx_regs(*curr_ctx), heap_base, heap_base + heap_size, 0 /* stack loc already in regs */, std::forward<T_Args>(params)...);
  }


  inline T_PointerType impl_malloc_in_sandbox(size_t size)
  {
    if constexpr (sizeof(size) > sizeof(uint32_t)) {
      detail::dynamic_check(size <= std::numeric_limits<uint32_t>::max(),
                            "Attempting to malloc more than the heap size");
    }

    void* ptr = lfi_lib_malloc(mLFIBox, lfi_thread_ctxp(mLFIMainThread), size);
    return reinterpret_cast<T_PointerType>(ptr);
  }

  inline void impl_free_in_sandbox(T_PointerType p)
  {
    lfi_lib_free(mLFIBox, lfi_thread_ctxp(mLFIMainThread), reinterpret_cast<void*>(p));
  }

  template<typename T_Ret, typename... T_Args>
  inline T_PointerType impl_register_callback(void* key, void* callback)
  {
    bool found = false;
    uint32_t found_loc = 0;
    void* chosen_interceptor = nullptr;

    RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);

    // need a compile time for loop as we we need I to be a compile time value
    // this is because we are setting the I'th callback interceptor
    lfi_detail::compile_time_for<MAX_CALLBACKS>([&](auto I) {
      constexpr auto i = I.value;
      if (!found && callback_info[i].callback == nullptr) {
        found = true;
        found_loc = i;

        chosen_interceptor =
          reinterpret_cast<void*>(callback_interceptor<i, T_Ret, T_Args...>);
      }
    });

    detail::dynamic_check(
      found,
      "Could not find an empty slot in sandbox function table. This would "
      "happen if you have registered too many callbacks, or unsandboxed "
      "too many function pointers. You can file a bug if you want to "
      "increase the maximum allowed callbacks or unsandboxed functions "
      "pointers");

    void* result = lfi_box_register_cb_struct(mLFIBox, chosen_interceptor);
    detail::dynamic_check(result, "LFI Register callback failed");

    rlbox_lfi_callback_info* curr_callback_info = &(callback_info[found_loc]);
    curr_callback_info->unique_key = key;
    curr_callback_info->callback = callback;
    curr_callback_info->sandbox_stub = result;
    curr_callback_info->interceptor_assignment = chosen_interceptor;

    callback_stub_hostfunc_map[result] = callback;

    return reinterpret_cast<T_PointerType>(result);
  }

  static inline std::pair<rlbox_lfi_sandbox*, void*>
  impl_get_executed_callback_sandbox_and_key()
  {
#ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
    auto& thread_data = *get_rlbox_lfi_sandbox_thread_data();
#endif
    auto sandbox = thread_data.sandbox;
    auto callback_num = thread_data.last_callback_invoked;
    void* key = sandbox->callback_info[callback_num].unique_key;
    return std::make_pair(sandbox, key);
  }

  template<typename T_Ret, typename... T_Args>
  inline void impl_unregister_callback(void* key)
  {
    bool found = false;
    uint32_t i = 0;
    {
      RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
      for (; i < MAX_CALLBACKS; i++) {
        if (callback_info[i].unique_key == key) {
          lfi_box_unregister_cb(mLFIBox, callback_info[i].interceptor_assignment);

          auto iter = callback_stub_hostfunc_map.find(callback_info[i].sandbox_stub);
          if (iter != callback_stub_hostfunc_map.end()) {
            callback_stub_hostfunc_map.erase(iter);
          }

          std::memset(&(callback_info[i]), 0, sizeof(rlbox_lfi_callback_info));
          found = true;
          break;
        }
      }
    }

    detail::dynamic_check(
      found, "Internal error: Could not find callback to unregister");

    return;
  }
};

} // namespace rlbox
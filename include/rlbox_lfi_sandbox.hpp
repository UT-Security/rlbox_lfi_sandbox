#pragma once

#include "lfi.h"
#include "lfi_tux.h"

// Pull the helper header from the main repo for dynamic_check and scope_exit
#include "rlbox_helpers.hpp"

#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
// RLBox allows applications to provide a custom shared lock implementation
#ifndef RLBOX_USE_CUSTOM_SHARED_LOCK
#  include <shared_mutex>
#endif
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <unistd.h>

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

extern "C" {
  extern void lfi_trampoline();
  // declare the static symbol with weak linkage to keep this header only
  __attribute__((weak)) thread_local void* lfi_retfn;
  __attribute__((weak)) thread_local void* lfi_targetfn;
}

namespace rlbox {

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

  ///////////////////////////////////////////////////////////////

  namespace prepend_arg_type_detail {
    template<typename T, typename T_ArgNew>
    struct helper;

    template<typename T_ArgNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_ArgNew>
    {
      using type = T_Ret(T_ArgNew, T_Args...);
    };
  }

  template<typename T_Func, typename T_ArgNew>
  using prepend_arg_type =
    typename prepend_arg_type_detail::helper<T_Func, T_ArgNew>::type;

  ///////////////////////////////////////////////////////////////

  namespace change_return_type_detail {
    template<typename T, typename T_RetNew>
    struct helper;

    template<typename T_RetNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_RetNew>
    {
      using type = T_RetNew(T_Args...);
    };
  }

  template<typename T_Func, typename T_RetNew>
  using change_return_type =
    typename change_return_type_detail::helper<T_Func, T_RetNew>::type;

  ///////////////////////////////////////////////////////////////

  namespace change_class_arg_types_detail {
    template<typename T, typename T_ArgNew>
    struct helper;

    template<typename T_ArgNew, typename T_Ret, typename... T_Args>
    struct helper<T_Ret(T_Args...), T_ArgNew>
    {
      using type =
        T_Ret(std::conditional_t<std::is_class_v<T_Args>, T_ArgNew, T_Args>...);
    };
  }

  template<typename T_Func, typename T_ArgNew>
  using change_class_arg_types =
    typename change_class_arg_types_detail::helper<T_Func, T_ArgNew>::type;

} // namespace lfi_detail


class rlbox_lfi_sandbox
{
public:
  using T_LongLongType = long long;
  using T_LongType = long;
  using T_IntType = int;
  using T_PointerType = uintptr_t;
  using T_ShortType = short;

private:
  struct TuxThread* mTuxThread {0};
  // mutable typename RLBOX_WASM_MODULE_TYPE_CURR::instance_t lfi_instance{ 0 };
  // struct w2c_env sandbox_memory_env{ 0 };
  // struct w2c_wasi__snapshot__preview1 wasi_env{ 0 };
  bool instance_initialized = false;
  // bool minwasi_init_inst_succeeded = false;
  // // Only used if memory and tables are imported
  // wasm_rt_memory_t local_sandbox_memory_info{ 0 };
  // mutable wasm_rt_funcref_table_t local_sandbox_callback_table{ 0 };
  // // Pointers to actual memory and table. This points to
  // // local_sandbox_memory_info and local_sandbox_callback_table if the Wasm
  // // module imports the memory and table.
  // wasm_rt_memory_t* sandbox_memory_info{ 0 };
  // mutable wasm_rt_funcref_table_t* sandbox_callback_table{ 0 };
  uintptr_t heap_base = 0;
  void* mLFIRetFn = 0;
  void* mLFIMallocFn = 0;
  void* mLFIFreeFn = 0;
  // size_t return_slot_size = 0;
  // T_PointerType return_slot = 0;
  // mutable std::vector<T_PointerType> callback_free_list;

  // static const size_t MAX_CALLBACKS = 128;
  // mutable RLBOX_SHARED_LOCK(callback_mutex);
  // void* callback_unique_keys[MAX_CALLBACKS]{ 0 };
  // void* callbacks[MAX_CALLBACKS]{ 0 };
  // uint32_t callback_slot_assignment[MAX_CALLBACKS]{ 0 };
  // mutable std::map<const void*, uint32_t> internal_callbacks;
  // mutable std::map<uint32_t, const void*> slot_assignments;

// #ifndef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
//   thread_local static inline rlbox_lfi_sandbox_thread_data thread_data{ 0,
//                                                                            0 };
// #endif

//   template<typename T_FormalRet, typename T_ActualRet>
//   inline auto serialize_to_sandbox(T_ActualRet arg)
//   {
//     if constexpr (std::is_class_v<T_FormalRet>) {
//       // structs returned as pointers into wasm memory/wasm stack
//       auto ptr = reinterpret_cast<T_FormalRet*>(
//         impl_get_unsandboxed_pointer<T_FormalRet*>(arg));
//       T_FormalRet ret = *ptr;
//       return ret;
//     } else {
//       return arg;
//     }
//   }

//   template<uint32_t N, typename T_Ret, typename... T_Args>
//   static typename lfi_detail::convert_type_to_wasm_type<T_Ret>::type
//   callback_interceptor(
//     void* /* vmContext */,
//     typename lfi_detail::convert_type_to_wasm_type<T_Args>::type... params)
//   {
// #ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
//     auto& thread_data = *get_rlbox_lfi_sandbox_thread_data();
// #endif
//     thread_data.last_callback_invoked = N;
//     using T_Func = T_Ret (*)(T_Args...);
//     T_Func func;
//     {
// #ifndef RLBOX_SINGLE_THREADED_INVOCATIONS
//       RLBOX_ACQUIRE_SHARED_GUARD(lock, thread_data.sandbox->callback_mutex);
// #endif
//       func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
//     }
//     // Callbacks are invoked through function pointers, cannot use std::forward
//     // as we don't have caller context for T_Args, which means they are all
//     // effectively passed by value
//     return func(
//       thread_data.sandbox->template serialize_to_sandbox<T_Args>(params)...);
//   }

//   template<uint32_t N, typename T_Ret, typename... T_Args>
//   static void callback_interceptor_promoted(
//     void* /* vmContext */,
//     typename lfi_detail::convert_type_to_wasm_type<T_Ret>::type ret,
//     typename lfi_detail::convert_type_to_wasm_type<T_Args>::type... params)
//   {
// #ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
//     auto& thread_data = *get_rlbox_lfi_sandbox_thread_data();
// #endif
//     thread_data.last_callback_invoked = N;
//     using T_Func = T_Ret (*)(T_Args...);
//     T_Func func;
//     {
// #ifndef RLBOX_SINGLE_THREADED_INVOCATIONS
//       RLBOX_ACQUIRE_SHARED_GUARD(lock, thread_data.sandbox->callback_mutex);
// #endif
//       func = reinterpret_cast<T_Func>(thread_data.sandbox->callbacks[N]);
//     }
//     // Callbacks are invoked through function pointers, cannot use std::forward
//     // as we don't have caller context for T_Args, which means they are all
//     // effectively passed by value
//     auto ret_val = func(
//       thread_data.sandbox->template serialize_to_sandbox<T_Args>(params)...);
//     // Copy the return value back
//     auto ret_ptr = reinterpret_cast<T_Ret*>(
//       thread_data.sandbox->template impl_get_unsandboxed_pointer<T_Ret*>(ret));
//     *ret_ptr = ret_val;
//   }

//   template<typename T_Ret, typename... T_Args>
//   inline wasm_rt_func_type_t get_lfi_func_index(
//     // dummy for template inference
//     T_Ret (*)(T_Args...) = nullptr) const
//   {
//     // Class return types as promoted to args
//     constexpr bool promoted = std::is_class_v<T_Ret>;
//     constexpr uint32_t param_count =
//       promoted ? (sizeof...(T_Args) + 1) : (sizeof...(T_Args));
//     constexpr uint32_t ret_count =
//       promoted ? 0 : (std::is_void_v<T_Ret> ? 0 : 1);

//     wasm_rt_func_type_t ret = nullptr;
//     if constexpr (ret_count == 0) {
//       ret = RLBOX_WASM_MODULE_TYPE_CURR::get_func_type(
//         param_count,
//         ret_count,
//         lfi_detail::convert_type_to_wasm_type<T_Args>::lfi_type...);
//     } else {
//       ret = RLBOX_WASM_MODULE_TYPE_CURR::get_func_type(
//         param_count,
//         ret_count,
//         lfi_detail::convert_type_to_wasm_type<T_Args>::lfi_type...,
//         lfi_detail::convert_type_to_wasm_type<T_Ret>::lfi_type);
//     }

//     return ret;
//   }

//   void ensure_return_slot_size(size_t size)
//   {
//     if (size > return_slot_size) {
//       if (return_slot_size) {
//         impl_free_in_sandbox(return_slot);
//       }
//       return_slot = impl_malloc_in_sandbox(size);
//       detail::dynamic_check(
//         return_slot != 0,
//         "Error initializing return slot. Sandbox may be out of memory!");
//       return_slot_size = size;
//     }
//   }

//   // function takes a 32-bit value and returns the next power of 2
//   // return is a 64-bit value as large 32-bit values will return 2^32
//   static inline uint64_t next_power_of_two(uint32_t value)
//   {
//     uint64_t power = 1;
//     while (power < value) {
//       power *= 2;
//     }
//     return power;
//   }

public:

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

    struct LFIPlatOptions platOptions {0};
    platOptions .pagesize = getpagesize();
    platOptions .vmsize = 4UL * 1024 * 1024 * 1024;
    struct LFIPlatform* plat = lfi_new_plat(platOptions );

    FALLIBLE_DYNAMIC_CHECK(
      infallible, plat, "Error loading LFI" /* lfi_strerror() */);

    struct TuxOptions tuxOptions {0};
    tuxOptions.pagesize = getpagesize();
    tuxOptions.stacksize = 2 * 1024 * 1024;
    tuxOptions.pause_on_exit = true;
    tuxOptions.verbose = false;
    struct Tux* tux = lfi_tux_new(plat, tuxOptions);

    FALLIBLE_DYNAMIC_CHECK(
      infallible, tux, "Error loading LFI Linux emulator" /* lfi_strerror() */);

    auto main_arg = std::make_unique<char[]>(32);
    strcpy(main_arg.get(), "rlbox_stub");
    char* args[] = { main_arg.get(), NULL};
    size_t size = (size_t)(lib_end - lib_start);
    mTuxThread = lfi_tux_proc_new(tux, &lib_start[0], size, 1, &args[0]);

    FALLIBLE_DYNAMIC_CHECK(
      infallible, mTuxThread, "lfi_tux_proc_new returned null");

    lfi_tux_proc_run(mTuxThread);

    heap_base = reinterpret_cast<uintptr_t>(impl_get_memory_location());

    uintptr_t heap_offset_mask = std::numeric_limits<uint32_t>::max();
    FALLIBLE_DYNAMIC_CHECK(infallible,
                            (heap_base & heap_offset_mask) == 0,
                            "Sandbox heap not aligned to 4GB");

    mLFIRetFn = impl_lookup_symbol("_lfi_retfn");
    FALLIBLE_DYNAMIC_CHECK(infallible,
                        mLFIRetFn,
                        "Return trampoline not found");

    // TODO: don't use wrappers
    mLFIMallocFn = impl_lookup_symbol("malloc_wrapper");
    FALLIBLE_DYNAMIC_CHECK(infallible,
                        mLFIMallocFn,
                        "Malloc not found");

    mLFIFreeFn = impl_lookup_symbol("free_wrapper");
    FALLIBLE_DYNAMIC_CHECK(infallible,
                        mLFIFreeFn,
                        "Free not found");

    instance_initialized = true;
    return true;
  }

#undef FALLIBLE_DYNAMIC_CHECK

  inline void impl_destroy_sandbox()
  {
    // TODO
    abort();
    // if (return_slot_size) {
    //   impl_free_in_sandbox(return_slot);
    // }

    // if (instance_initialized) {
    //   instance_initialized = false;
    //   RLBOX_WASM_MODULE_TYPE_CURR::free_instance(&lfi_instance);
    // }

    // if constexpr (is_imported_memory_and_table) {
    //   if (sandbox_memory_info && sandbox_memory_info->data) {
    //     destroy_lfi_memory(sandbox_memory_info);
    //     sandbox_memory_info = nullptr;
    //   }
    //   if (sandbox_callback_table && sandbox_callback_table->data) {
    //     wasm_rt_free_funcref_table(sandbox_callback_table);
    //     sandbox_callback_table = nullptr;
    //   }
    // }

    // if (minwasi_init_inst_succeeded) {
    //   minwasi_init_inst_succeeded = false;
    //   minwasi_cleanup_instance(&wasi_env);
    // }
  }

  void* impl_lookup_symbol(const char* func_name)
  {
    char* noconst_name = const_cast<char*>(func_name);
    return reinterpret_cast<void*>(lfi_proc_sym(lfi_tux_ctx(mTuxThread), noconst_name));
  }

  template<typename T>
  inline void* impl_get_unsandboxed_pointer(T_PointerType p) const
  {
    // if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
    //   RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
    //   auto found = slot_assignments.find(p);
    //   if (found != slot_assignments.end()) {
    //     auto ret = found->second;
    //     return const_cast<void*>(ret);
    //   } else {
    //     return nullptr;
    //   }
    // } else {
      return reinterpret_cast<void*>(heap_base | p);
    // }
  }

  template<typename T>
  inline T_PointerType impl_get_sandboxed_pointer(const void* p) const
  {
    // if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
    //   RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);

    //   uint32_t slot_number = 0;
    //   auto found = internal_callbacks.find(p);
    //   if (found != internal_callbacks.end()) {
    //     slot_number = found->second;
    //   } else {

    //     slot_number = new_callback_slot();
    //     wasm_rt_funcref_t func_val;
    //     func_val.func_type = get_lfi_func_index(static_cast<T>(nullptr));
    //     func_val.func =
    //       reinterpret_cast<wasm_rt_function_ptr_t>(const_cast<void*>(p));
    //     func_val.module_instance = &lfi_instance;

    //     sandbox_callback_table->data[slot_number] = func_val;
    //     internal_callbacks[p] = slot_number;
    //     slot_assignments[slot_number] = p;
    //   }
    //   return static_cast<T_PointerType>(slot_number);
    // } else {
      // we can assume that the heap is aligned and let integer truncation handle the conversion
      return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p));
    // }
  }

  template<typename T>
  static inline void* impl_get_unsandboxed_pointer_no_ctx(
    T_PointerType p,
    const void* example_unsandboxed_ptr,
    rlbox_lfi_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    // if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
    //   // swizzling function pointers needs access to the function pointer
    //   // tables and thus cannot be done without context
    //   auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
    //   return sandbox->template impl_get_unsandboxed_pointer<T>(p);
    // } else {
      // we can assume that the heap is aligned and grab the memory base from the example_unsandboxed_ptr
      uintptr_t heap_base_mask =
        std::numeric_limits<uintptr_t>::max() &
        ~(static_cast<uintptr_t>(std::numeric_limits<T_PointerType>::max()));
      uintptr_t computed_heap_base =
        reinterpret_cast<uintptr_t>(example_unsandboxed_ptr) & heap_base_mask;
      uintptr_t ret = computed_heap_base | p;
      return reinterpret_cast<void*>(ret);
    // }
  }

  template<typename T>
  static inline T_PointerType impl_get_sandboxed_pointer_no_ctx(
    const void* p,
    const void* example_unsandboxed_ptr,
    rlbox_lfi_sandbox* (*expensive_sandbox_finder)(
      const void* example_unsandboxed_ptr))
  {
    // if constexpr (std::is_function_v<std::remove_pointer_t<T>>) {
    //   // swizzling function pointers needs access to the function pointer
    //   // tables and thus cannot be done without context
    //   auto sandbox = expensive_sandbox_finder(example_unsandboxed_ptr);
    //   return sandbox->template impl_get_sandboxed_pointer<T>(p);
    // } else {
      // we can assume that the heap is aligned and let integer truncation handle the conversion
      RLBOX_LFI_UNUSED(example_unsandboxed_ptr);
      uintptr_t ret = reinterpret_cast<uintptr_t>(p);
      return static_cast<uint32_t>(ret);
    // }
  }

  static inline bool impl_is_in_same_sandbox(const void* p1, const void* p2)
  {
    uintptr_t heap_base_mask = std::numeric_limits<uintptr_t>::max() &
                               ~(std::numeric_limits<uint32_t>::max());
    return (reinterpret_cast<uintptr_t>(p1) & heap_base_mask) ==
           (reinterpret_cast<uintptr_t>(p2) & heap_base_mask);
  }

  inline bool impl_is_pointer_in_sandbox_memory(const void* p)
  {
    size_t length = impl_get_total_memory();
    uintptr_t p_val = reinterpret_cast<uintptr_t>(p);
    return p_val >= heap_base && p_val < (heap_base + length);
  }

  inline bool impl_is_pointer_in_app_memory(const void* p)
  {
    return !(impl_is_pointer_in_sandbox_memory(p));
  }

  inline size_t impl_get_total_memory() {
    return static_cast<uint64_t>(1) << 32;
  }

  inline void* impl_get_memory_location() const
  {
    return reinterpret_cast<void*>(lfi_as_info(lfi_ctx_as(lfi_tux_ctx(mTuxThread))).base);
  }

  template<typename T, typename T_Converted, typename... T_Args>
  auto impl_invoke_with_func_ptr(T_Converted* func_ptr, T_Args&&... params) -> lfi_detail::return_argument<T_Converted*>
  {
    lfi_retfn = mLFIRetFn;
    lfi_targetfn = (void*) func_ptr;

    T_Converted* trampoline = (T_Converted*) &lfi_trampoline;
    trampoline(params...);

    using T_Ret = lfi_detail::return_argument<T_Converted>;
    using T_NoVoidRet = std::conditional_t<std::is_void_v<T_Ret>, uint32_t, T_Ret>;

    T_NoVoidRet ret;

#define serialize_class_arg(a) a

    if constexpr (std::is_void_v<T_Ret>) {
      RLBOX_LFI_UNUSED(ret);
      trampoline(serialize_class_arg(params)...);
    } else {
      ret = trampoline(serialize_class_arg(params)...);
    }

    if constexpr (!std::is_void_v<T_Ret>) {
      return ret;
    }

    // TODO
    abort();

// #ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
//     auto& thread_data = *get_rlbox_lfi_sandbox_thread_data();
// #endif
//     auto old_sandbox = thread_data.sandbox;
//     thread_data.sandbox = this;
//     auto on_exit =
//       detail::make_scope_exit([&] { thread_data.sandbox = old_sandbox; });

//     // WASM functions are mangled in the following manner
//     // 1. All primitive types are left as is and follow an LP32 machine model
//     // (as opposed to the possibly 64-bit application)
//     // 2. All pointers are changed to u32 types
//     // 3. Returned class are returned as an out parameter before the actual
//     // function parameters
//     // 4. All class parameters are passed as pointers (u32 types)
//     // 5. The heap address is passed in as the first argument to the function
//     //
//     // RLBox accounts for the first 2 differences in T_Converted type, but we
//     // need to handle the rest

//     // Handle point 3
//     using T_Ret = lfi_detail::return_argument<T_Converted>;
//     if constexpr (std::is_class_v<T_Ret>) {
//       using T_Conv1 = lfi_detail::change_return_type<T_Converted, void>;
//       using T_Conv2 = lfi_detail::prepend_arg_type<T_Conv1, T_PointerType>;
//       auto func_ptr_conv =
//         reinterpret_cast<T_Conv2*>(reinterpret_cast<uintptr_t>(func_ptr));
//       ensure_return_slot_size(sizeof(T_Ret));
//       impl_invoke_with_func_ptr<T>(func_ptr_conv, return_slot, params...);

//       auto ptr = reinterpret_cast<T_Ret*>(
//         impl_get_unsandboxed_pointer<T_Ret*>(return_slot));
//       T_Ret ret = *ptr;
//       return ret;
//     }

//     // Handle point 4
//     constexpr size_t alloc_length = [&] {
//       if constexpr (sizeof...(params) > 0) {
//         return ((std::is_class_v<T_Args> ? 1 : 0) + ...);
//       } else {
//         return 0;
//       }
//     }();

//     // 0 arg functions create 0 length arrays which is not allowed
//     T_PointerType allocations_buff[alloc_length == 0 ? 1 : alloc_length];
//     T_PointerType* allocations = allocations_buff;

//     auto serialize_class_arg =
//       [&](auto arg) -> std::conditional_t<std::is_class_v<decltype(arg)>,
//                                           T_PointerType,
//                                           decltype(arg)> {
//       using T_Arg = decltype(arg);
//       if constexpr (std::is_class_v<T_Arg>) {
//         auto slot = impl_malloc_in_sandbox(sizeof(T_Arg));
//         auto ptr =
//           reinterpret_cast<T_Arg*>(impl_get_unsandboxed_pointer<T_Arg*>(slot));
//         *ptr = arg;
//         allocations[0] = slot;
//         allocations++;
//         return slot;
//       } else {
//         return arg;
//       }
//     };

//     // 0 arg functions don't use serialize
//     RLBOX_LFI_UNUSED(serialize_class_arg);

//     using T_ConvNoClass =
//       lfi_detail::change_class_arg_types<T_Converted, T_PointerType>;

//     // Handle Point 5
//     using T_ConvHeap = lfi_detail::prepend_arg_type<
//       T_ConvNoClass,
//       typename RLBOX_WASM_MODULE_TYPE_CURR::instance_t*>;

//     // Function invocation
//     auto func_ptr_conv =
//       reinterpret_cast<T_ConvHeap*>(reinterpret_cast<uintptr_t>(func_ptr));

//     using T_NoVoidRet =
//       std::conditional_t<std::is_void_v<T_Ret>, uint32_t, T_Ret>;
//     T_NoVoidRet ret;

//     if constexpr (std::is_void_v<T_Ret>) {
//       RLBOX_LFI_UNUSED(ret);
//       func_ptr_conv(&lfi_instance, serialize_class_arg(params)...);
//     } else {
//       ret = func_ptr_conv(&lfi_instance, serialize_class_arg(params)...);
//     }

//     for (size_t i = 0; i < alloc_length; i++) {
//       impl_free_in_sandbox(allocations_buff[i]);
//     }

//     if constexpr (!std::is_void_v<T_Ret>) {
//       return ret;
//     }
  }

  inline T_PointerType impl_malloc_in_sandbox(size_t size)
  {
    if constexpr (sizeof(size) > sizeof(uint32_t)) {
      detail::dynamic_check(size <= std::numeric_limits<uint32_t>::max(),
                            "Attempting to malloc more than the heap size");
    }

    using T_Func = void*(size_t);
    using T_Converted = T_PointerType(uint32_t);

    T_PointerType ret = impl_invoke_with_func_ptr<T_Func, T_Converted>(
      reinterpret_cast<T_Converted*>(mLFIMallocFn),
      static_cast<uint32_t>(size));
    return ret;
  }

  inline void impl_free_in_sandbox(T_PointerType p)
  {
    using T_Func = void(void*);
    using T_Converted = void(T_PointerType);
    impl_invoke_with_func_ptr<T_Func, T_Converted>(
      reinterpret_cast<T_Converted*>(mLFIFreeFn),
      p);
  }

private:
  // // Should be called with callback_mutex held
  // uint32_t new_callback_slot() const
  // {
  //   if (callback_free_list.size() > 0) {
  //     uint32_t ret = callback_free_list.back();
  //     callback_free_list.pop_back();
  //     return ret;
  //   }

  //   const uint32_t curr_size = sandbox_callback_table->size;

  //   detail::dynamic_check(
  //     curr_size < sandbox_callback_table->max_size,
  //     "Could not find an empty row in Wasm instance table. This would "
  //     "happen if you have registered too many callbacks, or unsandboxed "
  //     "too many function pointers.");

  //   wasm_rt_funcref_t func_val{ 0 };
  //   // on success, this returns the previous number of elements in the table
  //   const uint32_t ret =
  //     wasm_rt_grow_funcref_table(sandbox_callback_table, 1, func_val);

  //   detail::dynamic_check(
  //     ret != 0 && ret != (uint32_t)-1,
  //     "Adding a new callback slot to the wasm instance failed.");

  //   // We have expanded the number of slots
  //   // Previous slots size: ret
  //   // New slot is at index: ret
  //   const uint32_t slot_number = ret;
  //   return slot_number;
  // }

  // void free_callback_slot(uint32_t slot) const
  // {
  //   callback_free_list.push_back(slot);
  // }

public:
  template<typename T_Ret, typename... T_Args>
  inline T_PointerType impl_register_callback(void* key, void* callback)
  {
    // TODO
    abort();
    // bool found = false;
    // uint32_t found_loc = 0;
    // wasm_rt_function_ptr_t chosen_interceptor = nullptr;

    // RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);

    // // need a compile time for loop as we we need I to be a compile time value
    // // this is because we are setting the I'th callback ineterceptor
    // lfi_detail::compile_time_for<MAX_CALLBACKS>([&](auto I) {
    //   constexpr auto i = I.value;
    //   if (!found && callbacks[i] == nullptr) {
    //     found = true;
    //     found_loc = i;

    //     if constexpr (std::is_class_v<T_Ret>) {
    //       chosen_interceptor = (wasm_rt_function_ptr_t)(
    //         callback_interceptor_promoted<i, T_Ret, T_Args...>);
    //     } else {
    //       chosen_interceptor =
    //         (wasm_rt_function_ptr_t)(callback_interceptor<i, T_Ret, T_Args...>);
    //     }
    //   }
    // });

    // detail::dynamic_check(
    //   found,
    //   "Could not find an empty slot in sandbox function table. This would "
    //   "happen if you have registered too many callbacks, or unsandboxed "
    //   "too many function pointers. You can file a bug if you want to "
    //   "increase the maximum allowed callbacks or unsadnboxed functions "
    //   "pointers");

    // wasm_rt_funcref_t func_val;
    // func_val.func_type = get_lfi_func_index<T_Ret, T_Args...>();
    // func_val.func = chosen_interceptor;
    // func_val.module_instance = &lfi_instance;

    // const uint32_t slot_number = new_callback_slot();
    // sandbox_callback_table->data[slot_number] = func_val;

    // callback_unique_keys[found_loc] = key;
    // callbacks[found_loc] = callback;
    // callback_slot_assignment[found_loc] = slot_number;
    // slot_assignments[slot_number] = callback;

    // return static_cast<T_PointerType>(slot_number);
  }

  static inline std::pair<rlbox_lfi_sandbox*, void*>
  impl_get_executed_callback_sandbox_and_key()
  {
    // TODO
    abort();
// #ifdef RLBOX_EMBEDDER_PROVIDES_TLS_STATIC_VARIABLES
//     auto& thread_data = *get_rlbox_lfi_sandbox_thread_data();
// #endif
//     auto sandbox = thread_data.sandbox;
//     auto callback_num = thread_data.last_callback_invoked;
//     void* key = sandbox->callback_unique_keys[callback_num];
//     return std::make_pair(sandbox, key);
  }

  template<typename T_Ret, typename... T_Args>
  inline void impl_unregister_callback(void* key)
  {
    // TODO
    abort();
//     bool found = false;
//     uint32_t i = 0;
//     {
//       RLBOX_ACQUIRE_UNIQUE_GUARD(lock, callback_mutex);
//       for (; i < MAX_CALLBACKS; i++) {
//         if (callback_unique_keys[i] == key) {
//           const uint32_t slot_number = callback_slot_assignment[i];
//           wasm_rt_funcref_t func_val{ 0 };
//           sandbox_callback_table->data[slot_number] = func_val;

//           callback_unique_keys[i] = nullptr;
//           callbacks[i] = nullptr;
//           callback_slot_assignment[i] = 0;
//           found = true;
//           break;
//         }
//       }
//     }

//     detail::dynamic_check(
//       found, "Internal error: Could not find callback to unregister");

//     return;
  }
};

}; // namespace rlbox

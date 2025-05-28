
#pragma once

#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <type_traits>

#include "lfi.h"

extern "C" {
extern void *lfi_trampoline;

// eliminate these definitions
struct ElfTable {
    char* tab;
    size_t size;
};

struct LFIContext {
    void* kstackp;
    uintptr_t tp;
    struct TuxRegs regs;
    void* ctxp;
    struct Sys* sys;
    struct LFIAddrSpace* as;

    uintptr_t elfbase;
    struct ElfTable symtab;
    struct ElfTable strtab;
};

}

#include "lfi_ctx_offsets.h"

namespace sepstack_invoker_detail {

template <typename T> static constexpr bool true_v = true;

//////////////////

template <typename T_ExitFunc> class scope_exit {
  T_ExitFunc exit_func;
  bool released;

public:
  explicit scope_exit(T_ExitFunc &&cleanup)
      : exit_func(cleanup), released(true) {}

  scope_exit(scope_exit &&rhs)
      : exit_func(std::move(rhs.exit_func)), released(rhs.released) {
    rhs.release();
  }

  ~scope_exit() {
    if (released) {
      exit_func();
    }
  }

  void release() { released = false; }

private:
  explicit scope_exit(const scope_exit &) = delete;
  scope_exit &operator=(const scope_exit &) = delete;
  scope_exit &operator=(scope_exit &&) = delete;
};

template <typename T_ExitFunc>
[[nodiscard]] scope_exit<T_ExitFunc>
make_scope_exit(T_ExitFunc &&exitFunction) {
  return scope_exit<T_ExitFunc>(std::move(exitFunction));
}

//////////////////

static constexpr uintptr_t align_round_up(uintptr_t val, uintptr_t alignment) {
  return (val + alignment - 1) & ~(alignment - 1);
}

static constexpr uintptr_t align_round_down(uintptr_t val,
                                            uintptr_t alignment) {
  return val & ~(alignment - 1);
}
///////////////

enum class param_location_t {
  INT_REG,
  FLOAT_REG,
  INT_REG2,
  STACK,
  STACK_REFERENCE_IN_REG,
  STACK_REFERENCE_IN_STACK,
};

enum class ret_location_t {
  STACK_REFERENCE_IN_REG,
  STACK_REFERENCE_IN_STACK,
  // A classification used when values will overwrite existing data in
  // registers. Used by simple return values
  REUSE_REG
};

template <typename T>
static constexpr bool is_trival_destr_and_copy_v =
    std::is_trivially_destructible_v<T>
        &&std::is_trivially_copy_constructible_v<T>;

template <typename T>
static constexpr bool is_class_with_trival_destr_and_copy_v =
    std::is_class_v<T> &&is_trival_destr_and_copy_v<T>;

struct return_info_t {
  unsigned int int_registers_used;

  unsigned int stack_space;
  // Extra space for returns whose value is on the stack. We make space and then
  // take a reference to the space.
  unsigned int extra_stackdata_space;

  ret_location_t destination;
};

template <unsigned int TotalParams> struct param_info_t {
  unsigned int stack_space;

  // Extra space for data that needs to be copied.
  // For example, structs that are not "is_trival_destr_and_copy_v" are passed
  // by reference We need to first copy the object and then take a reference to
  // the copy The below field is the space needed for such copies
  unsigned int extra_stackdata_space;

  std::array<param_location_t, TotalParams> destinations;
};

enum class REG_TYPE { INT, FLOAT };

//////////////////

template <unsigned int TIntRegsLeft, typename TRet>
constexpr return_info_t classify_return() {
  return_info_t ret{0};
  ret.destination = ret_location_t::REUSE_REG;

  if constexpr (!std::is_void_v<TRet>) {
    if constexpr (std::is_class_v<TRet> && sizeof(TRet) > 16) {
      ret.extra_stackdata_space = sizeof(TRet);
      if constexpr (TIntRegsLeft > 0) {
        ret.destination = ret_location_t::STACK_REFERENCE_IN_REG;
        ret.int_registers_used = 1;
      } else {
        ret.destination = ret_location_t::STACK_REFERENCE_IN_STACK;
        ret.stack_space = sizeof(void *);
      }
    }
  }

  return ret;
}

template <unsigned int TIntRegsLeft, unsigned int TFloatRegsLeft,
          unsigned int I, unsigned int TotalParams>
constexpr param_info_t<TotalParams> classify_params() {
  param_info_t<TotalParams> ret{0, 0, {}};
  return ret;
}

template <unsigned int TIntRegsLeft, unsigned int TFloatRegsLeft,
          unsigned int I, unsigned int TotalParams, typename TFormalParam,
          typename... TFormalParams>
constexpr param_info_t<TotalParams> classify_params() {

  if constexpr (TFloatRegsLeft > 0 && std::is_floating_point_v<TFormalParam>) {
    auto ret = classify_params<TIntRegsLeft, TFloatRegsLeft - 1, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::FLOAT_REG;
    return ret;
  } else if constexpr (TIntRegsLeft > 0 &&
                       (std::is_integral_v<TFormalParam> ||
                        std::is_pointer_v<TFormalParam> ||
                        std::is_lvalue_reference_v<TFormalParam> ||
                        std::is_enum_v<TFormalParam> ||
                        is_class_with_trival_destr_and_copy_v<
                            TFormalParam>)&&sizeof(TFormalParam) <=
                           sizeof(void *)) {
    auto ret = classify_params<TIntRegsLeft - 1, TFloatRegsLeft, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::INT_REG;
    return ret;
  } else if constexpr (TIntRegsLeft > 1 &&
                       (std::is_integral_v<TFormalParam> ||
                        is_class_with_trival_destr_and_copy_v<
                            TFormalParam>)&&sizeof(TFormalParam) >
                           sizeof(void *) &&
                       sizeof(TFormalParam) <= 2 * sizeof(void *)) {
    auto ret = classify_params<TIntRegsLeft - 2, TFloatRegsLeft, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::INT_REG2;
    return ret;
  } else if constexpr (TIntRegsLeft > 0 && std::is_class_v<TFormalParam> &&
                       !is_trival_destr_and_copy_v<TFormalParam>) {
    auto ret = classify_params<TIntRegsLeft - 1, TFloatRegsLeft, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::STACK_REFERENCE_IN_REG;
    ret.extra_stackdata_space += align_round_up(sizeof(TFormalParam), sizeof(uintptr_t));
    return ret;
  } else if constexpr (TIntRegsLeft == 0 && std::is_class_v<TFormalParam> &&
                       !is_trival_destr_and_copy_v<TFormalParam>) {
    auto ret = classify_params<TIntRegsLeft, TFloatRegsLeft, I + 1, TotalParams,
                               TFormalParams...>();
    ret.destinations[I] = param_location_t::STACK_REFERENCE_IN_STACK;
    ret.stack_space += sizeof(void *);
    ret.extra_stackdata_space += align_round_up(sizeof(TFormalParam), sizeof(uintptr_t));
    return ret;
  } else {
    auto ret = classify_params<TIntRegsLeft, TFloatRegsLeft, I + 1, TotalParams,
                               TFormalParams...>();
    ret.destinations[I] = param_location_t::STACK;
    ret.stack_space += align_round_up(sizeof(TFormalParam), sizeof(uintptr_t));
    return ret;
  }
}

void set_register(LFIContext* ctx, REG_TYPE type, unsigned int reg_num, uint64_t *value) {
#if defined(unix) || defined(__unix) || defined(__unix__) || defined(linux) || \
    defined(__linux) || defined(__linux__)

#  if defined(_M_X64) || defined(__x86_64__)
  if (type == REG_TYPE::INT) {
    if (reg_num == 0) {
      ctx->regs.rdi = *value;
    } else if (reg_num == 1) {
      ctx->regs.rsi = *value;
    } else if (reg_num == 2) {
      ctx->regs.rdx = *value;
    } else if (reg_num == 3) {
      ctx->regs.rcx = *value;
    } else if (reg_num == 4) {
      ctx->regs.r8 = *value;
    } else if (reg_num == 5) {
      ctx->regs.r9 = *value;
    }
  } else if (type == REG_TYPE::FLOAT) {
    if (reg_num == 0) {
      ctx->regs.xmm[0] = *value;
    } else if (reg_num == 1) {
      ctx->regs.xmm[1] = *value;
    } else if (reg_num == 2) {
      ctx->regs.xmm[2] = *value;
    } else if (reg_num == 3) {
      ctx->regs.xmm[3] = *value;
    } else if (reg_num == 4) {
      ctx->regs.xmm[4] = *value;
    } else if (reg_num == 5) {
      ctx->regs.xmm[5] = *value;
    } else if (reg_num == 6) {
      ctx->regs.xmm[6] = *value;
    } else if (reg_num == 7) {
      ctx->regs.xmm[7] = *value;
    }
  }
#  else
#    error "Unsupported architecture"
#  endif

#else
#  error "Unsupported OS"
#endif
}

//////////////////

template <unsigned int I, unsigned int TotalParams, unsigned int IntRegParams,
          unsigned int FloatRegParams,
          std::array<param_location_t, TotalParams> ParamDestinations>
void push_param(LFIContext* ctx, uintptr_t stackloc, uintptr_t stack_extradata_loc) {}

template <unsigned int I, unsigned int TotalParams, unsigned int IntRegParams,
          unsigned int FloatRegParams,
          std::array<param_location_t, TotalParams> ParamDestinations,
          typename TFormalParam, typename... TFormalParams,
          typename TActualParam, typename... TActualParams>
void push_param(LFIContext* ctx, uintptr_t stackloc, uintptr_t stack_extradata_loc,
                TActualParam arg, TActualParams &&...args) {
  if constexpr (ParamDestinations[I] == param_location_t::STACK) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    memcpy((char *)stackloc, &argCast, sizeof(argCast));
    stackloc += align_round_up(sizeof(argCast), sizeof(uintptr_t));

    push_param<I + 1, TotalParams, IntRegParams, FloatRegParams,
               ParamDestinations, TFormalParams...>(ctx,
        stackloc, stack_extradata_loc, std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] == param_location_t::INT_REG) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    uint64_t copy = 0;
    if constexpr (std::is_lvalue_reference_v<TFormalParam>) {
      auto ptr = &argCast;
      memcpy(&copy, &ptr, sizeof(void *));
    } else {
      memcpy(&copy, &argCast, sizeof(argCast));
    }
    set_register(ctx, REG_TYPE::INT, IntRegParams, &copy);

    push_param<I + 1, TotalParams, IntRegParams + 1, FloatRegParams,
               ParamDestinations, TFormalParams...>(ctx,
        stackloc, stack_extradata_loc, std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] == param_location_t::INT_REG2) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]), &argCast, sizeof(argCast));
    set_register(ctx, REG_TYPE::INT, IntRegParams, &(copy[0]));
    set_register(ctx, REG_TYPE::INT, IntRegParams + 1, &(copy[1]));

    push_param<I + 1, TotalParams, IntRegParams + 2, FloatRegParams,
               ParamDestinations, TFormalParams...>(ctx,
        stackloc, stack_extradata_loc, std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] == param_location_t::FLOAT_REG) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    // Use a large buffer to handle cases for SIMD args
    uint64_t copy[4] = {0};
    memcpy(&(copy[0]), &argCast, sizeof(argCast));
    set_register(ctx, REG_TYPE::FLOAT, FloatRegParams, copy);

    push_param<I + 1, TotalParams, IntRegParams + 1, FloatRegParams,
               ParamDestinations, TFormalParams...>(ctx,
        stackloc, stack_extradata_loc, std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::STACK_REFERENCE_IN_REG) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    // TODO: not safe. Call the copy constructor?
    memcpy((char *)stack_extradata_loc, &argCast, sizeof(argCast));

    set_register(ctx, REG_TYPE::INT, IntRegParams, &stack_extradata_loc);

    stack_extradata_loc += align_round_up(sizeof(argCast), sizeof(uintptr_t));

    push_param<I + 1, TotalParams, IntRegParams + 1, FloatRegParams,
               ParamDestinations, TFormalParams...>(ctx,
        stackloc, stack_extradata_loc, std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::STACK_REFERENCE_IN_STACK) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    // TODO: not safe. Call the copy constructor?
    memcpy((char *)stack_extradata_loc, &argCast, sizeof(argCast));

    memcpy((char *)stackloc, &stack_extradata_loc, sizeof(TFormalParam *));
    stackloc += sizeof(TFormalParam *);

    stack_extradata_loc += align_round_up(sizeof(argCast), sizeof(uintptr_t));

    push_param<I + 1, TotalParams, IntRegParams, FloatRegParams,
               ParamDestinations, TFormalParams...>(ctx,
        stackloc, stack_extradata_loc, std::forward<TActualParams>(args)...);

  } else {
    abort();
  }
}

template <unsigned int TotalParams, ret_location_t RetDestination,
          std::array<param_location_t, TotalParams> ParamDestinations,
          typename TRet, typename... TFormalParams, typename... TActualParams>
void* push_return_and_params(LFIContext* ctx, uintptr_t stackloc, uintptr_t stack_extradata_loc,
                            TActualParams &&...args) {

  uintptr_t *ret = 0;
  if constexpr (RetDestination == ret_location_t::STACK_REFERENCE_IN_REG) {
    ret = &stack_extradata_loc;
    set_register(ctx, REG_TYPE::INT, 0, ret);
    stack_extradata_loc += sizeof(TRet);
  } else if constexpr (RetDestination ==
                       ret_location_t::STACK_REFERENCE_IN_STACK) {
    ret = &stack_extradata_loc;
    memcpy((char *)stackloc, ret, sizeof(TRet *));
    stackloc += sizeof(TRet *);
    stack_extradata_loc += sizeof(TRet);
  } else if constexpr (RetDestination == ret_location_t::REUSE_REG) {
    // noop
  } else {
    abort();
  }

  constexpr unsigned int IntRegParams =
      (RetDestination == ret_location_t::STACK_REFERENCE_IN_REG) ? 1 : 0;
  push_param<0, TotalParams, IntRegParams, 0, ParamDestinations,
             TFormalParams...>(ctx, stackloc, stack_extradata_loc,
                               std::forward<TActualParams>(args)...);
  return ret;
}

template <typename TRet, typename... TFormalParams, typename... TActualParams>
auto invoke_func_on_separate_stack_helper(LFIContext* ctx, TRet (*dummy)(TFormalParams...),
                                          TActualParams &&...args) {

#if defined(unix) || defined(__unix) || defined(__unix__) || defined(linux) || \
    defined(__linux) || defined(__linux__)

#  if defined(_M_X64) || defined(__x86_64__)
  constexpr unsigned int int_regs_left = 6;
  constexpr unsigned int float_regs_left = 8;
  // Stack alignment is usually 16. However, there are some corner cases such as
  // use of __m256 that require 32 alignment. So we can always align to 32 to
  // keep things safe.
  constexpr unsigned int expected_stack_alignment = 32;
// #  elif defined(__aarch64__)
//   constexpr unsigned int int_regs_left = 8;
//   constexpr unsigned int float_regs_left = 8;
//   constexpr unsigned int expected_stack_alignment = 16;
// #  elif defined(_WIN32)
//   constexpr unsigned int int_regs_left = 4;
//   constexpr unsigned int float_regs_left = 4;
//   constexpr unsigned int expected_stack_alignment = 16;
#  else
#    error "Unsupported architecture"
#  endif

#else
#  error "Unsupported OS"
#endif

  constexpr return_info_t ret_info = classify_return<int_regs_left, TRet>();

  constexpr param_info_t param_info =
      classify_params<int_regs_left - ret_info.int_registers_used,
                      float_regs_left, 0, sizeof...(TFormalParams),
                      TFormalParams...>();

  uintptr_t stack_extradata_loc = ctx->regs.rsp -
                                  ret_info.extra_stackdata_space -
                                  param_info.extra_stackdata_space;

  ctx->regs.rsp = align_round_down(
      stack_extradata_loc - ret_info.stack_space - param_info.stack_space,
      expected_stack_alignment);

  void *return_slot = push_return_and_params<sizeof...(TFormalParams), ret_info.destination,
                         param_info.destinations, TRet, TFormalParams...>(ctx,
      ctx->regs.rsp, stack_extradata_loc,
      std::forward<TActualParams>(args)...);

  uintptr_t trampoline_addr =
      reinterpret_cast<uintptr_t>(&lfi_trampoline);

  if constexpr (ret_info.destination == ret_location_t::REUSE_REG) {
    TRet (*target_func_ptr)() = 0;
    memcpy(reinterpret_cast<void *>(&target_func_ptr), &trampoline_addr,
           sizeof(void *));
    return (*target_func_ptr)();
  } else {
    void (*target_func_ptr)() = 0;
    memcpy(reinterpret_cast<void *>(&target_func_ptr), &trampoline_addr,
           sizeof(void *));
    (*target_func_ptr)();

    TRet ret;
    memcpy(&ret, return_slot, sizeof(TRet));
    return ret;
  }
};

namespace memberfuncptr_to_cfuncptr_detail {
template <typename Ret, typename... Args>
auto helper(Ret (*)(Args...)) -> Ret (*)(Args...);

template <typename Ret, typename F, typename... Args>
auto helper(Ret (F::*)(Args...)) -> Ret (*)(F *, Args...);

template <typename Ret, typename F, typename... Args>
auto helper(Ret (F::*)(Args...) const) -> Ret (*)(const F *, Args...);

template <typename F> auto helper(F) -> decltype(helper(&F::operator()));
} // namespace memberfuncptr_to_cfuncptr_detail

template <typename T>
using memberfuncptr_to_cfuncptr_t =
    decltype(memberfuncptr_to_cfuncptr_detail::helper(std::declval<T>()));

}; // namespace sepstack_invoker_detail

template <typename TFuncPtr, typename... TActualParams>
auto invoke_func_on_separate_stack(LFIContext* ctx,
                                  uintptr_t sbx_stack_loc,
                                   TActualParams &&...args) {

  static_assert(
      std::is_invocable_v<std::remove_pointer_t<TFuncPtr>, TActualParams...>,
      "Calling function with incorrect parameters");

  using TCFuncPtr =
      sepstack_invoker_detail::memberfuncptr_to_cfuncptr_t<TFuncPtr>;

  auto prev_host_stack_ptr = ctx->kstackp;

  auto prev_sbx_stack_ptr = ctx->regs.rsp;
  ctx->regs.rsp =
      prev_sbx_stack_ptr != 0 ? prev_sbx_stack_ptr : sbx_stack_loc;

  auto restore_context = sepstack_invoker_detail::make_scope_exit([&]() {
    ctx->kstackp = prev_host_stack_ptr;
    ctx->regs.rsp = prev_sbx_stack_ptr;
  });

  return sepstack_invoker_detail::invoke_func_on_separate_stack_helper(ctx,
      static_cast<TCFuncPtr>(0), std::forward<TActualParams>(args)...);
}

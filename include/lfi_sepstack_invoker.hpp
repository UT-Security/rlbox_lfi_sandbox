#pragma once

#include <array>
#include <limits>
#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tuple>
#include <type_traits>
#include <utility>

#include "lfi.h"

extern "C" {

extern void lfi_trampoline();
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
//////////////////

enum class param_location_t {
  INT_REG,
  FLOAT_REG,
  INT_REG2,
  INT_FLOAT_REG,
  FLOAT_INT_REG,
  FLOAT_REG2,
  STACK,
  STACK_REFERENCE_IN_REG,
  STACK_REFERENCE_IN_STACK,
};

enum class ret_location_t {
  INT_REG,
  FLOAT_REG,
  INT_REG2,
  INT_FLOAT_REG,
  FLOAT_INT_REG,
  FLOAT_REG2,
  // Stack refs specified as a paremeter in a reg or stack but output in reg
  STACK_REFERENCE_IN_REG_OUT_REG,
  STACK_REFERENCE_IN_STACK_OUT_REG,
  NONE,
};

template <typename T>
static constexpr bool is_trival_destr_and_copy_v =
    std::is_trivially_destructible_v<T> &&
    std::is_trivially_copy_constructible_v<T>;

template <typename T>
static constexpr bool is_class_with_trival_destr_and_copy_v =
    std::is_class_v<T> && is_trival_destr_and_copy_v<T>;

template <typename T>
static constexpr bool is_one_reg_size = sizeof(T) <= sizeof(void *);
template <typename T>
static constexpr bool is_two_reg_size = sizeof(T) > sizeof(void *) &&
                                        sizeof(T) <= 2 * sizeof(void *);

//////////////////

// From https://github.com/yosh-matsuda/field-reflection

namespace detail {
template <typename T, std::size_t = 0> struct any_lref {
  template <typename U>
    requires(!std::same_as<U, T>)
  constexpr operator U &() const && noexcept; // NOLINT
  template <typename U>
    requires(!std::same_as<U, T>)
  constexpr operator U &() const & noexcept; // NOLINT
};

template <typename T, std::size_t = 0> struct any_rref {
  template <typename U>
    requires(!std::same_as<U, T>)
  constexpr operator U() const && noexcept; // NOLINT
};

template <typename T, std::size_t = 0> struct any_lref_no_base {
  template <typename U>
    requires(!std::is_base_of_v<U, T> && !std::same_as<U, T>)
  constexpr operator U &() const && noexcept; // NOLINT
  template <typename U>
    requires(!std::is_base_of_v<U, T> && !std::same_as<U, T>)
  constexpr operator U &() const & noexcept; // NOLINT
};

template <typename T, std::size_t = 0> struct any_rref_no_base {
  template <typename U>
    requires(!std::is_base_of_v<U, T> && !std::same_as<U, T>)
  constexpr operator U() const && noexcept; // NOLINT
};

template <typename T, std::size_t ArgNum>
concept constructible =
    (ArgNum == 0 && requires { T{}; }) ||
    []<std::size_t I0, std::size_t... Is>(std::index_sequence<I0, Is...>) {
      if constexpr (std::is_copy_constructible_v<T>) {
        return requires { T{any_lref_no_base<T, I0>(), any_lref<T, Is>()...}; };
      } else {
        return requires { T{any_rref_no_base<T, I0>(), any_rref<T, Is>()...}; };
      }
    }(std::make_index_sequence<ArgNum>());

template <typename T, std::size_t N>
  requires std::is_aggregate_v<T>
constexpr std::size_t field_count_max3 = []() {
  if constexpr (N >= 3) {
    return std::numeric_limits<std::size_t>::max();
  } else if constexpr (constructible<T, N> && !constructible<T, N + 1>) {
    return N;
  } else {
    return field_count_max3<T, N + 1>;
  }
}();

template <typename T> constexpr bool is_pair_class_impl() {
  if constexpr (std::is_aggregate_v<T>) {
    return detail::field_count_max3<T, 0> == 2;
  }
  return false;
}
}; // namespace detail

template <typename T>
static constexpr bool is_pair_class = detail::is_pair_class_impl<T>();

namespace detail {
template <typename T>
auto get_pair_class_first_type() -> decltype([](T p) {
  if constexpr (is_pair_class<T>) {
    auto [a, b] = p;
    return a;
  }
}(std::declval<T>()));

template <typename T>
auto get_pair_class_second_type() -> decltype([](T p) {
  if constexpr (is_pair_class<T>) {
    auto [a, b] = p;
    return b;
  }
}(std::declval<T>()));
}; // namespace detail

template <typename T>
using pair_class_first_type = decltype(detail::get_pair_class_first_type<T>());

template <typename T>
using pair_class_second_type =
    decltype(detail::get_pair_class_second_type<T>());

//////////////////

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

#if defined(unix) || defined(__unix) || defined(__unix__) || defined(linux) || \
    defined(__linux) || defined(__linux__)

#  if defined(__x86_64__) || defined(_M_X64)
static constexpr unsigned int int_regs_available = 6;
static constexpr unsigned int float_regs_available = 8;
// Stack alignment is usually 16. However, there are some corner cases such as
// use of __m256 that require 32 alignment. So we can always align to 32 to
// keep things safe.
static constexpr unsigned int expected_stack_alignment = 32;
static constexpr unsigned int stack_param_offset = 8;
// Do pair structs (structs with two fields) of type <uint64_t, double> when
// passed as parameters (or return values) get treated as a uint64_t and double?
// If yes, this is true. Else if they are treated as two uint64_t, this is
// false.
static constexpr bool mixed_pair_structs_supported = true;
// When returning a large struct, the caller passes in a pointer to the memory
// location where the callee should write the struct. If this pointer is
// specified in one of the parameter registers, this value should be true, else
// false.
static constexpr bool returnslot_ptr_reg_consumes_parameter = true;
#  elif defined(__aarch64__)
static constexpr unsigned int int_regs_available = 8;
static constexpr unsigned int float_regs_available = 8;
static constexpr unsigned int expected_stack_alignment = 16;
static constexpr unsigned int stack_param_offset = 0;
// Do pair structs (structs with two fields) of type <uint64_t, double> when
// passed as parameters (or return values) get treated as a uint64_t and double?
// If yes, this is true. Else if they are treated as two uint64_t, this is
// false.
static constexpr bool mixed_pair_structs_supported = false;
// When returning a large struct, the caller passes in a pointer to the memory
// location where the callee should write the struct. If this pointer is
// specified in one of the parameter registers, this value should be true, else
// false.
static constexpr bool returnslot_ptr_reg_consumes_parameter = false;
#  else
#    error "Unsupported architecture"
#  endif

#elif defined(_WIN32)

#  if defined(__x86_64__) || defined(_M_X64)
static constexpr unsigned int int_regs_available = 4;
static constexpr unsigned int float_regs_available = 4;
static constexpr unsigned int expected_stack_alignment = 16;
static constexpr unsigned int stack_param_offset = 8;
#  else
#    error "Unsupported architecture"
#  endif

#else
#  error "Unsupported OS"
#endif

//////////////////

template <unsigned int TIntRegsLeft, typename TRet>
constexpr return_info_t classify_return() {
  return_info_t ret{0};

  using NoVoid_TRet = std::conditional_t<std::is_void_v<TRet>, int, TRet>;

  if constexpr (std::is_void_v<TRet>) {
    ret.destination = ret_location_t::NONE;
  } else if constexpr (std::is_class_v<TRet> &&
                       (!is_class_with_trival_destr_and_copy_v<TRet> ||
                        sizeof(NoVoid_TRet) > 16)) {
    ret.extra_stackdata_space = sizeof(TRet);
    if constexpr (TIntRegsLeft > 0) {
      ret.destination = ret_location_t::STACK_REFERENCE_IN_REG_OUT_REG;
      ret.int_registers_used = 1;
    } else {
      ret.destination = ret_location_t::STACK_REFERENCE_IN_STACK_OUT_REG;
      ret.stack_space = sizeof(void *);
    }
  } else if constexpr (std::is_floating_point_v<TRet>) {
    ret.destination = ret_location_t::FLOAT_REG;
  } else if constexpr (is_one_reg_size<NoVoid_TRet> &&
                       (std::is_integral_v<TRet> || std::is_pointer_v<TRet> ||
                        std::is_lvalue_reference_v<TRet> ||
                        std::is_enum_v<TRet> ||
                        is_class_with_trival_destr_and_copy_v<TRet>)) {
    ret.destination = ret_location_t::INT_REG;
  } else if constexpr (is_two_reg_size<NoVoid_TRet> &&
                       std::is_integral_v<TRet>) {
    ret.destination = ret_location_t::INT_REG2;
  } else if constexpr (is_two_reg_size<NoVoid_TRet> &&
                       is_class_with_trival_destr_and_copy_v<TRet> &&
                       is_pair_class<TRet> &&
                       std::is_floating_point_v<pair_class_first_type<TRet>> &&
                       std::is_floating_point_v<pair_class_second_type<TRet>>) {
    ret.destination = ret_location_t::FLOAT_REG2;
  } else if constexpr (is_two_reg_size<NoVoid_TRet> &&
                       is_class_with_trival_destr_and_copy_v<TRet> &&
                       is_pair_class<TRet> && mixed_pair_structs_supported &&
                       std::is_integral_v<pair_class_first_type<TRet>> &&
                       std::is_floating_point_v<pair_class_second_type<TRet>>) {
    ret.destination = ret_location_t::INT_FLOAT_REG;
  } else if constexpr (is_two_reg_size<NoVoid_TRet> &&
                       is_class_with_trival_destr_and_copy_v<TRet> &&
                       is_pair_class<TRet> && mixed_pair_structs_supported &&
                       std::is_floating_point_v<pair_class_first_type<TRet>> &&
                       std::is_integral_v<pair_class_second_type<TRet>>) {
    ret.destination = ret_location_t::FLOAT_INT_REG;
  } else if constexpr (is_two_reg_size<NoVoid_TRet> &&
                       is_class_with_trival_destr_and_copy_v<TRet> &&
                       is_pair_class<TRet>) {
    ret.destination = ret_location_t::INT_REG2;
  } else {
    static_assert(!true_v<TRet>, "Unknown case");
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
  } else if constexpr (is_one_reg_size<TFormalParam> && TIntRegsLeft > 0 &&
                       (std::is_integral_v<TFormalParam> ||
                        std::is_pointer_v<TFormalParam> ||
                        std::is_lvalue_reference_v<TFormalParam> ||
                        std::is_enum_v<TFormalParam> ||
                        is_class_with_trival_destr_and_copy_v<TFormalParam>)) {
    auto ret = classify_params<TIntRegsLeft - 1, TFloatRegsLeft, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::INT_REG;
    return ret;
  } else if constexpr (is_two_reg_size<TFormalParam> && TIntRegsLeft > 1 &&
                       std::is_integral_v<TFormalParam>) {
    auto ret = classify_params<TIntRegsLeft - 2, TFloatRegsLeft, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::INT_REG2;
    return ret;
  } else if constexpr (is_two_reg_size<TFormalParam> && TIntRegsLeft > 1 &&
                       is_class_with_trival_destr_and_copy_v<TFormalParam> &&
                       is_pair_class<TFormalParam> &&
                       std::is_floating_point_v<
                           pair_class_first_type<TFormalParam>> &&
                       std::is_floating_point_v<
                           pair_class_second_type<TFormalParam>>) {
    auto ret = classify_params<TIntRegsLeft, TFloatRegsLeft - 2, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::FLOAT_REG2;
    return ret;
  } else if constexpr (is_two_reg_size<TFormalParam> && TIntRegsLeft > 1 &&
                       is_class_with_trival_destr_and_copy_v<TFormalParam> &&
                       is_pair_class<TFormalParam> &&
                       mixed_pair_structs_supported &&
                       std::is_integral_v<
                           pair_class_first_type<TFormalParam>> &&
                       std::is_floating_point_v<
                           pair_class_second_type<TFormalParam>>) {
    auto ret = classify_params<TIntRegsLeft - 1, TFloatRegsLeft - 1, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::INT_FLOAT_REG;
    return ret;
  } else if constexpr (is_two_reg_size<TFormalParam> && TIntRegsLeft > 1 &&
                       is_class_with_trival_destr_and_copy_v<TFormalParam> &&
                       is_pair_class<TFormalParam> &&
                       mixed_pair_structs_supported &&
                       std::is_floating_point_v<
                           pair_class_first_type<TFormalParam>> &&
                       std::is_integral_v<
                           pair_class_second_type<TFormalParam>>) {
    auto ret = classify_params<TIntRegsLeft - 1, TFloatRegsLeft - 1, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::FLOAT_INT_REG;
    return ret;
  } else if constexpr (is_two_reg_size<TFormalParam> && TIntRegsLeft > 1 &&
                       is_class_with_trival_destr_and_copy_v<TFormalParam> &&
                       is_pair_class<TFormalParam>) {
    auto ret = classify_params<TIntRegsLeft - 2, TFloatRegsLeft, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::INT_REG2;
    return ret;
  } else if constexpr (TIntRegsLeft > 0 && std::is_class_v<TFormalParam> &&
                       !is_trival_destr_and_copy_v<TFormalParam>) {
    auto ret = classify_params<TIntRegsLeft - 1, TFloatRegsLeft, I + 1,
                               TotalParams, TFormalParams...>();
    ret.destinations[I] = param_location_t::STACK_REFERENCE_IN_REG;
    ret.extra_stackdata_space +=
        align_round_up(sizeof(TFormalParam), sizeof(uintptr_t));
    return ret;
  } else if constexpr (TIntRegsLeft == 0 && std::is_class_v<TFormalParam> &&
                       !is_trival_destr_and_copy_v<TFormalParam>) {
    auto ret = classify_params<TIntRegsLeft, TFloatRegsLeft, I + 1, TotalParams,
                               TFormalParams...>();
    ret.destinations[I] = param_location_t::STACK_REFERENCE_IN_STACK;
    ret.stack_space += sizeof(void *);
    ret.extra_stackdata_space +=
        align_round_up(sizeof(TFormalParam), sizeof(uintptr_t));
    return ret;
  } else {
    auto ret = classify_params<TIntRegsLeft, TFloatRegsLeft, I + 1, TotalParams,
                               TFormalParams...>();
    ret.destinations[I] = param_location_t::STACK;
    ret.stack_space += align_round_up(sizeof(TFormalParam), sizeof(uintptr_t));
    return ret;
  }
}

#if defined(unix) || defined(__unix) || defined(__unix__) || defined(linux) || \
    defined(__linux) || defined(__linux__)

#  if defined(__x86_64__) || defined(_M_X64)

static uint64_t &get_param_register_ref(LFIContext *ctx, REG_TYPE type,
                                        unsigned int reg_num) {
  if (type == REG_TYPE::INT) {
    if (reg_num == 0) {
      return ctx->regs.rdi;
    } else if (reg_num == 1) {
      return ctx->regs.rsi;
    } else if (reg_num == 2) {
      return ctx->regs.rdx;
    } else if (reg_num == 3) {
      return ctx->regs.rcx;
    } else if (reg_num == 4) {
      return ctx->regs.r8;
    } else if (reg_num == 5) {
      return ctx->regs.r9;
    }
  } else if (type == REG_TYPE::FLOAT) {
    if (reg_num == 0) {
      return ctx->regs.xmm[0];
    } else if (reg_num == 1) {
      return ctx->regs.xmm[1];
    } else if (reg_num == 2) {
      return ctx->regs.xmm[2];
    } else if (reg_num == 3) {
      return ctx->regs.xmm[3];
    } else if (reg_num == 4) {
      return ctx->regs.xmm[4];
    } else if (reg_num == 5) {
      return ctx->regs.xmm[5];
    } else if (reg_num == 6) {
      return ctx->regs.xmm[6];
    } else if (reg_num == 7) {
      return ctx->regs.xmm[7];
    }
  }
  abort();
}

static uint64_t &get_return_register_ref(LFIContext *ctx, REG_TYPE type,
                                         unsigned int reg_num) {
  if (type == REG_TYPE::INT) {
    if (reg_num == 0) {
      return ctx->regs.rax;
    } else if (reg_num == 1) {
      return ctx->regs.rdx;
    }
  } else if (type == REG_TYPE::FLOAT) {
    if (reg_num == 0) {
      return ctx->regs.xmm[0];
    } else if (reg_num == 1) {
      return ctx->regs.xmm[1];
    }
  }

  abort();
}

static uint64_t &get_return_slotptr_register_ref(LFIContext *ctx) {
  return ctx->regs.rdi;
}

static uint64_t &get_stack_register_ref(LFIContext *ctx) {
  return ctx->regs.rsp;
}

#  elif defined(__aarch64__) || defined(_M_ARM64)

static uint64_t &get_param_register_ref(LFIContext *ctx, REG_TYPE type,
                                        unsigned int reg_num) {
  if (type == REG_TYPE::INT) {
    if (reg_num == 0) {
      return ctx->regs.x0;
    } else if (reg_num == 1) {
      return ctx->regs.x1;
    } else if (reg_num == 2) {
      return ctx->regs.x2;
    } else if (reg_num == 3) {
      return ctx->regs.x3;
    } else if (reg_num == 4) {
      return ctx->regs.x4;
    } else if (reg_num == 5) {
      return ctx->regs.x5;
    } else if (reg_num == 6) {
      return ctx->regs.x6;
    } else if (reg_num == 7) {
      return ctx->regs.x7;
    }
  } else if (type == REG_TYPE::FLOAT) {
    if (reg_num == 0) {
      return ctx->regs.vector[0];
    } else if (reg_num == 1) {
      return ctx->regs.vector[2];
    } else if (reg_num == 2) {
      return ctx->regs.vector[4];
    } else if (reg_num == 3) {
      return ctx->regs.vector[6];
    } else if (reg_num == 4) {
      return ctx->regs.vector[8];
    } else if (reg_num == 5) {
      return ctx->regs.vector[10];
    } else if (reg_num == 6) {
      return ctx->regs.vector[12];
    } else if (reg_num == 7) {
      return ctx->regs.vector[14];
    }
  }
  abort();
}

static uint64_t &get_return_register_ref(LFIContext *ctx, REG_TYPE type,
                                         unsigned int reg_num) {
  if (type == REG_TYPE::INT) {
    if (reg_num == 0) {
      return ctx->regs.x0;
    } else if (reg_num == 1) {
      return ctx->regs.x1;
    }
  } else if (type == REG_TYPE::FLOAT) {
    if (reg_num == 0) {
      return ctx->regs.vector[0];
    } else if (reg_num == 1) {
      return ctx->regs.vector[2];
    }
  }

  abort();
}

static uint64_t &get_return_slotptr_register_ref(LFIContext *ctx) {
  return ctx->regs.x8;
}

static uint64_t &get_stack_register_ref(LFIContext *ctx) {
  return ctx->regs.sp;
}

#  else
#    error "Unsupported architecture"
#  endif

#else
#  error "Unsupported OS"
#endif

//////////////////

static void safe_range(uintptr_t sbx_mem_start, uintptr_t sbx_mem_end,
                       uintptr_t start, uintptr_t end) {
  if (start > end)
    abort();
  if (start < sbx_mem_start || start > sbx_mem_end)
    abort();
  if (end < sbx_mem_start || end > sbx_mem_end)
    abort();
}

template <unsigned int I, unsigned int TotalParams, unsigned int IntRegParams,
          unsigned int FloatRegParams,
          std::array<param_location_t, TotalParams> ParamDestinations>
void push_param(LFIContext *ctx, uintptr_t sbx_mem_start,
                uintptr_t sbx_mem_end, uintptr_t stackloc,
                uintptr_t stack_extradata_loc) {}

template <unsigned int I, unsigned int TotalParams, unsigned int IntRegParams,
          unsigned int FloatRegParams,
          std::array<param_location_t, TotalParams> ParamDestinations,
          typename TFormalParam, typename... TFormalParams,
          typename TActualParam, typename... TActualParams>
void push_param(LFIContext *ctx, uintptr_t sbx_mem_start,
                uintptr_t sbx_mem_end, uintptr_t stackloc,
                uintptr_t stack_extradata_loc, TActualParam arg,
                TActualParams &&...args) {
  if constexpr (ParamDestinations[I] == param_location_t::STACK) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    safe_range(sbx_mem_start, sbx_mem_end, stackloc,
               stackloc + sizeof(argCast));
    memcpy((char *)stackloc, &argCast, sizeof(argCast));
    stackloc += align_round_up(sizeof(argCast), sizeof(uintptr_t));

    push_param<I + 1, TotalParams, IntRegParams, FloatRegParams,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] == param_location_t::INT_REG) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    uint64_t copy = 0;
    if constexpr (std::is_lvalue_reference_v<TFormalParam>) {
      auto ptr = &argCast;
      memcpy(&copy, &ptr, sizeof(void *));
    } else {
      memcpy(&copy, &argCast, sizeof(argCast));
    }
    get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams) = copy;

    push_param<I + 1, TotalParams, IntRegParams + 1, FloatRegParams,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] == param_location_t::INT_REG2) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]), &argCast, sizeof(argCast));
    get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams) = copy[0];
    get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams + 1) = copy[1];

    push_param<I + 1, TotalParams, IntRegParams + 2, FloatRegParams,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);
  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::INT_FLOAT_REG) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]), &argCast, sizeof(argCast));
    get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams) = copy[0];
    get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams) = copy[1];

    push_param<I + 1, TotalParams, IntRegParams + 1, FloatRegParams + 1,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);
  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::FLOAT_INT_REG) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]), &argCast, sizeof(argCast));
    get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams) = copy[0];
    get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams) = copy[1];

    push_param<I + 1, TotalParams, IntRegParams + 1, FloatRegParams + 1,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);
  } else if constexpr (ParamDestinations[I] == param_location_t::FLOAT_REG2) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]), &argCast, sizeof(argCast));
    get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams) = copy[0];
    get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams + 1) = copy[1];

    push_param<I + 1, TotalParams, IntRegParams, FloatRegParams + 2,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] == param_location_t::FLOAT_REG) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    // Use a large buffer to handle cases for SIMD args
    uint64_t copy[4] = {0};
    memcpy(&(copy[0]), &argCast, sizeof(argCast));
    get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams) = copy[0];

    push_param<I + 1, TotalParams, IntRegParams, FloatRegParams + 1,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::STACK_REFERENCE_IN_REG) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    safe_range(sbx_mem_start, sbx_mem_end, stack_extradata_loc,
               stack_extradata_loc + sizeof(argCast));
    memcpy((char *)stack_extradata_loc, &argCast, sizeof(argCast));

    get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams) =
        stack_extradata_loc;

    stack_extradata_loc += align_round_up(sizeof(argCast), sizeof(uintptr_t));

    push_param<I + 1, TotalParams, IntRegParams + 1, FloatRegParams,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);

  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::STACK_REFERENCE_IN_STACK) {

    TFormalParam argCast = static_cast<TFormalParam>(arg);
    safe_range(sbx_mem_start, sbx_mem_end, stack_extradata_loc,
               stack_extradata_loc + sizeof(argCast));
    memcpy((char *)stack_extradata_loc, &argCast, sizeof(argCast));

    safe_range(sbx_mem_start, sbx_mem_end, stackloc,
               stackloc + sizeof(TFormalParam *));
    memcpy((char *)stackloc, &stack_extradata_loc, sizeof(TFormalParam *));
    stackloc += sizeof(TFormalParam *);

    stack_extradata_loc += align_round_up(sizeof(argCast), sizeof(uintptr_t));

    push_param<I + 1, TotalParams, IntRegParams, FloatRegParams,
               ParamDestinations, TFormalParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc, stack_extradata_loc,
        std::forward<TActualParams>(args)...);

  } else {
    abort();
  }
}

template <unsigned int TotalParams, ret_location_t RetDestination,
          std::array<param_location_t, TotalParams> ParamDestinations,
          typename TRet, typename... TFormalParams, typename... TActualParams>
void *push_return_and_params(LFIContext *ctx, uintptr_t sbx_mem_start,
                             uintptr_t sbx_mem_end, uintptr_t stackloc,
                             uintptr_t stack_extradata_loc,
                             TActualParams &&...args) {

  uintptr_t ret = 0;
  if constexpr (RetDestination ==
                ret_location_t::STACK_REFERENCE_IN_REG_OUT_REG) {
    ret = stack_extradata_loc;
    get_return_slotptr_register_ref(ctx) = ret;
    safe_range(sbx_mem_start, sbx_mem_end, stack_extradata_loc,
               stack_extradata_loc + sizeof(TRet));
    stack_extradata_loc += sizeof(TRet);
  } else if constexpr (RetDestination ==
                       ret_location_t::STACK_REFERENCE_IN_STACK_OUT_REG) {
    ret = stack_extradata_loc;
    safe_range(sbx_mem_start, sbx_mem_end, stackloc, stackloc + sizeof(TRet *));
    memcpy((char *)stackloc, &ret, sizeof(TRet *));
    stackloc += sizeof(TRet *);
    safe_range(sbx_mem_start, sbx_mem_end, stack_extradata_loc,
               stack_extradata_loc + sizeof(TRet));
    stack_extradata_loc += sizeof(TRet);
  } else if constexpr (RetDestination == ret_location_t::INT_REG ||
                       RetDestination == ret_location_t::INT_REG2 ||
                       RetDestination == ret_location_t::INT_FLOAT_REG ||
                       RetDestination == ret_location_t::FLOAT_INT_REG ||
                       RetDestination == ret_location_t::FLOAT_REG2 ||
                       RetDestination == ret_location_t::FLOAT_REG ||
                       RetDestination == ret_location_t::NONE) {
    // noop
  } else {
    abort();
  }

  constexpr unsigned int IntRegParams =
      (RetDestination == ret_location_t::STACK_REFERENCE_IN_REG_OUT_REG &&
       returnslot_ptr_reg_consumes_parameter)
          ? 1
          : 0;
  push_param<0, TotalParams, IntRegParams, 0, ParamDestinations,
             TFormalParams...>(ctx, sbx_mem_start, sbx_mem_end, stackloc,
                               stack_extradata_loc,
                               std::forward<TActualParams>(args)...);

  return (void *)ret;
}

template <typename TRet, typename... TFormalParams, typename... TActualParams>
auto invoke_func_on_separate_stack_helper(LFIContext *ctx,
                                          uintptr_t sbx_mem_start,
                                          uintptr_t sbx_mem_end,
                                          TRet (*dummy)(TFormalParams...),
                                          TActualParams &&...args) {
  constexpr return_info_t ret_info =
      classify_return<int_regs_available, TRet>();

  constexpr param_info_t param_info =
      classify_params<int_regs_available - ret_info.int_registers_used,
                      float_regs_available, 0, sizeof...(TFormalParams),
                      TFormalParams...>();

  uintptr_t stack_extradata_loc = get_stack_register_ref(ctx) -
                                  ret_info.extra_stackdata_space -
                                  param_info.extra_stackdata_space;

  uintptr_t new_stack_loc = align_round_down(
      stack_extradata_loc - ret_info.stack_space - param_info.stack_space,
      expected_stack_alignment);

  get_stack_register_ref(ctx) = new_stack_loc;

  void *return_slot =
      push_return_and_params<sizeof...(TFormalParams), ret_info.destination,
                             param_info.destinations, TRet, TFormalParams...>(
          ctx, sbx_mem_start, sbx_mem_end, new_stack_loc, stack_extradata_loc,
          std::forward<TActualParams>(args)...);

  lfi_trampoline();

  if constexpr (ret_info.destination == ret_location_t::NONE) {
    // noop
  } else if constexpr (ret_info.destination == ret_location_t::INT_REG ||
                       ret_info.destination == ret_location_t::FLOAT_REG) {
    TRet ret;
    uintptr_t *src = ret_info.destination == ret_location_t::INT_REG
                         ? &get_return_register_ref(ctx, REG_TYPE::INT, 0)
                         : &get_return_register_ref(ctx, REG_TYPE::FLOAT, 0);
    memcpy(&ret, src, sizeof(TRet));
    return ret;
  } else if constexpr (ret_info.destination == ret_location_t::INT_REG2) {
    uint64_t copy[2];
    copy[0] = get_return_register_ref(ctx, REG_TYPE::INT, 0);
    copy[1] = get_return_register_ref(ctx, REG_TYPE::INT, 1);

    TRet ret;
    memcpy(&ret, copy, sizeof(TRet));
    return ret;
  } else if constexpr (ret_info.destination == ret_location_t::INT_FLOAT_REG) {
    uint64_t copy[2];
    copy[0] = get_return_register_ref(ctx, REG_TYPE::INT, 0);
    copy[1] = get_return_register_ref(ctx, REG_TYPE::FLOAT, 0);

    TRet ret;
    memcpy(&ret, copy, sizeof(TRet));
    return ret;
  } else if constexpr (ret_info.destination == ret_location_t::FLOAT_INT_REG) {
    uint64_t copy[2];
    copy[0] = get_return_register_ref(ctx, REG_TYPE::FLOAT, 0);
    copy[1] = get_return_register_ref(ctx, REG_TYPE::INT, 0);

    TRet ret;
    memcpy(&ret, copy, sizeof(TRet));
    return ret;
  } else if constexpr (ret_info.destination == ret_location_t::FLOAT_REG2) {
    uint64_t copy[2];
    copy[0] = get_return_register_ref(ctx, REG_TYPE::FLOAT, 0);
    copy[1] = get_return_register_ref(ctx, REG_TYPE::FLOAT, 1);

    TRet ret;
    memcpy(&ret, copy, sizeof(TRet));
    return ret;
  } else {
    TRet ret;
    memcpy(&ret, return_slot, sizeof(TRet));
    return ret;
  }
}

template <unsigned int I, unsigned int TotalParams, unsigned int IntRegParams,
          unsigned int FloatRegParams,
          std::array<param_location_t, TotalParams> ParamDestinations>
std::tuple<> collect_params_from_context_noret(LFIContext *ctx,
                                               uintptr_t sbx_mem_start,
                                               uintptr_t sbx_mem_end,
                                               uintptr_t stackloc) {
  return std::tuple<>{};
}

template <unsigned int I, unsigned int TotalParams, unsigned int IntRegParams,
          unsigned int FloatRegParams,
          std::array<param_location_t, TotalParams> ParamDestinations,
          typename TParam, typename... TParams>
std::tuple<TParam, TParams...>
collect_params_from_context_noret(LFIContext *ctx,
                                  uintptr_t sbx_mem_start,
                                  uintptr_t sbx_mem_end, uintptr_t stackloc) {
  if constexpr (ParamDestinations[I] == param_location_t::STACK) {
    TParam arg;
    safe_range(sbx_mem_start, sbx_mem_end, stackloc, stackloc + sizeof(arg));
    memcpy(&arg, (char *)stackloc, sizeof(arg));
    stackloc += align_round_up(sizeof(arg), sizeof(uintptr_t));

    auto rem = collect_params_from_context_noret<I + 1, TotalParams,
                                                 IntRegParams, FloatRegParams,
                                                 ParamDestinations, TParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;
  } else if constexpr (ParamDestinations[I] == param_location_t::INT_REG) {
    TParam arg;
    memcpy(&arg, &get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams),
           sizeof(arg));

    auto rem =
        collect_params_from_context_noret<I + 1, TotalParams, IntRegParams + 1,
                                          FloatRegParams, ParamDestinations,
                                          TParams...>(ctx, sbx_mem_start,
                                                      sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;
  } else if constexpr (ParamDestinations[I] == param_location_t::INT_REG2) {
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]),
           &get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams),
           sizeof(copy[0]));
    memcpy(&(copy[1]),
           &get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams + 1),
           sizeof(copy[1]));

    TParam arg;
    memcpy(&arg, copy, sizeof(arg));

    auto rem =
        collect_params_from_context_noret<I + 1, TotalParams, IntRegParams + 2,
                                          FloatRegParams, ParamDestinations,
                                          TParams...>(ctx, sbx_mem_start,
                                                      sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;
  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::INT_FLOAT_REG) {
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]),
           &get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams),
           sizeof(copy[0]));
    memcpy(&(copy[1]),
           &get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams),
           sizeof(copy[1]));

    TParam arg;
    memcpy(&arg, copy, sizeof(arg));

    auto rem =
        collect_params_from_context_noret<I + 1, TotalParams, IntRegParams + 1,
                                          FloatRegParams + 1, ParamDestinations,
                                          TParams...>(ctx, sbx_mem_start,
                                                      sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;
  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::FLOAT_INT_REG) {
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]),
           &get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams),
           sizeof(copy[0]));
    memcpy(&(copy[1]),
           &get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams),
           sizeof(copy[1]));

    TParam arg;
    memcpy(&arg, copy, sizeof(arg));

    auto rem =
        collect_params_from_context_noret<I + 1, TotalParams, IntRegParams + 1,
                                          FloatRegParams + 1, ParamDestinations,
                                          TParams...>(ctx, sbx_mem_start,
                                                      sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;
  } else if constexpr (ParamDestinations[I] == param_location_t::FLOAT_REG2) {
    uint64_t copy[2] = {0, 0};
    memcpy(&(copy[0]),
           &get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams),
           sizeof(copy[0]));
    memcpy(&(copy[1]),
           &get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams + 1),
           sizeof(copy[1]));

    TParam arg;
    memcpy(&arg, copy, sizeof(arg));

    auto rem =
        collect_params_from_context_noret<I + 1, TotalParams, IntRegParams,
                                          FloatRegParams + 2, ParamDestinations,
                                          TParams...>(ctx, sbx_mem_start,
                                                      sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;
  } else if constexpr (ParamDestinations[I] == param_location_t::FLOAT_REG) {
    TParam arg;
    memcpy(&arg, &get_param_register_ref(ctx, REG_TYPE::FLOAT, FloatRegParams),
           sizeof(arg));

    auto rem =
        collect_params_from_context_noret<I + 1, TotalParams, IntRegParams,
                                          FloatRegParams + 1, ParamDestinations,
                                          TParams...>(ctx, sbx_mem_start,
                                                      sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;
  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::STACK_REFERENCE_IN_REG) {
    uintptr_t stack_ref =
        get_param_register_ref(ctx, REG_TYPE::INT, IntRegParams);
    TParam arg;
    safe_range(sbx_mem_start, sbx_mem_end, stack_ref, stack_ref + sizeof(arg));
    memcpy(&arg, (char *)stack_ref, sizeof(arg));

    auto rem =
        collect_params_from_context_noret<I + 1, TotalParams, IntRegParams + 1,
                                          FloatRegParams, ParamDestinations,
                                          TParams...>(ctx, sbx_mem_start,
                                                      sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;

  } else if constexpr (ParamDestinations[I] ==
                       param_location_t::STACK_REFERENCE_IN_STACK) {
    uintptr_t stack_ref = 0;
    safe_range(sbx_mem_start, sbx_mem_end, stackloc,
               stackloc + sizeof(stack_ref));
    memcpy(&stack_ref, (char *)stackloc, sizeof(stack_ref));
    stackloc += sizeof(TParam *);

    TParam arg;
    safe_range(sbx_mem_start, sbx_mem_end, stack_ref, stack_ref + sizeof(arg));
    memcpy(&arg, (char *)stack_ref, sizeof(arg));

    auto rem = collect_params_from_context_noret<I + 1, TotalParams,
                                                 IntRegParams, FloatRegParams,
                                                 ParamDestinations, TParams...>(
        ctx, sbx_mem_start, sbx_mem_end, stackloc);
    auto ret = std::tuple_cat(std::make_tuple(arg), rem);
    return ret;
  } else {
    abort();
  }
}

template <unsigned int TotalParams, ret_location_t RetDestination,
          std::array<param_location_t, TotalParams> ParamDestinations,
          typename TRet, typename... TParams>
std::tuple<TParams...>
collect_params_from_context(LFIContext *ctx, uintptr_t sbx_mem_start,
                            uintptr_t sbx_mem_end, uintptr_t stackloc,
                            uintptr_t *out_ret_slot) {

  *out_ret_slot = 0;
  stackloc += stack_param_offset;

  if constexpr (RetDestination ==
                ret_location_t::STACK_REFERENCE_IN_STACK_OUT_REG) {
    *out_ret_slot = stackloc;
    stackloc += sizeof(TRet *);
  } else if constexpr (RetDestination ==
                       ret_location_t::STACK_REFERENCE_IN_REG_OUT_REG) {
    *out_ret_slot = get_return_slotptr_register_ref(ctx);
  }

  constexpr unsigned int IntRegParams =
      (RetDestination == ret_location_t::STACK_REFERENCE_IN_REG_OUT_REG &&
       returnslot_ptr_reg_consumes_parameter)
          ? 1
          : 0;
  return collect_params_from_context_noret<0, TotalParams, IntRegParams, 0,
                                           ParamDestinations, TParams...>(
      ctx, sbx_mem_start, sbx_mem_end, stackloc);
}

template <typename TRet, typename... TParams>
void invoke_callback_from_separate_stack_helper(LFIContext *ctx,
                                                uintptr_t sbx_mem_start,
                                                uintptr_t sbx_mem_end,
                                                TRet (*func_ptr)(TParams...)) {
  constexpr return_info_t ret_info =
      classify_return<int_regs_available, TRet>();

  constexpr param_info_t param_info =
      classify_params<int_regs_available - ret_info.int_registers_used,
                      float_regs_available, 0, sizeof...(TParams),
                      TParams...>();

  uintptr_t ret_slot = 0;
  auto params =
      collect_params_from_context<sizeof...(TParams), ret_info.destination,
                                  param_info.destinations, TRet, TParams...>(
          ctx, sbx_mem_start, sbx_mem_end, get_stack_register_ref(ctx),
          &ret_slot);

  if constexpr (ret_info.destination == ret_location_t::NONE) {
    std::apply(func_ptr, params);
  } else if constexpr (ret_info.destination == ret_location_t::INT_REG) {
    TRet ret = std::apply(func_ptr, params);
    uintptr_t copy = 0;
    memcpy(&copy, &ret, sizeof(TRet));
    get_return_register_ref(ctx, REG_TYPE::INT, 0) = copy;
  } else if constexpr (ret_info.destination == ret_location_t::INT_REG2) {
    TRet ret = std::apply(func_ptr, params);
    uintptr_t copy[2]{0};
    memcpy(copy, &ret, sizeof(TRet));
    get_return_register_ref(ctx, REG_TYPE::INT, 0) = copy[0];
    get_return_register_ref(ctx, REG_TYPE::INT, 1) = copy[1];
  } else if constexpr (ret_info.destination == ret_location_t::INT_FLOAT_REG) {
    TRet ret = std::apply(func_ptr, params);
    uintptr_t copy[2]{0};
    memcpy(copy, &ret, sizeof(TRet));
    get_return_register_ref(ctx, REG_TYPE::INT, 0) = copy[0];
    get_return_register_ref(ctx, REG_TYPE::FLOAT, 0) = copy[1];
  } else if constexpr (ret_info.destination == ret_location_t::FLOAT_INT_REG) {
    TRet ret = std::apply(func_ptr, params);
    uintptr_t copy[2]{0};
    memcpy(copy, &ret, sizeof(TRet));
    get_return_register_ref(ctx, REG_TYPE::FLOAT, 0) = copy[0];
    get_return_register_ref(ctx, REG_TYPE::INT, 0) = copy[1];
  } else if constexpr (ret_info.destination == ret_location_t::FLOAT_REG2) {
    TRet ret = std::apply(func_ptr, params);
    uintptr_t copy[2]{0};
    memcpy(copy, &ret, sizeof(TRet));
    get_return_register_ref(ctx, REG_TYPE::FLOAT, 0) = copy[0];
    get_return_register_ref(ctx, REG_TYPE::FLOAT, 1) = copy[1];
  } else if constexpr (ret_info.destination == ret_location_t::FLOAT_REG) {
    TRet ret = std::apply(func_ptr, params);
    uint64_t copy = 0;
    memcpy(&copy, &ret, sizeof(TRet));
    get_return_register_ref(ctx, REG_TYPE::FLOAT, 0) = copy;
  } else if constexpr (ret_info.destination ==
                           ret_location_t::STACK_REFERENCE_IN_REG_OUT_REG ||
                       ret_info.destination ==
                           ret_location_t::STACK_REFERENCE_IN_STACK_OUT_REG) {
    TRet ret = std::apply(func_ptr, params);
    // set return register
    get_return_register_ref(ctx, REG_TYPE::INT, 0) = ret_slot;
    // copy ret to sbx stack
    safe_range(sbx_mem_start, sbx_mem_end, ret_slot, ret_slot + sizeof(TRet));
    memcpy((char *)ret_slot, &ret, sizeof(TRet));
  } else {
    static_assert(!true_v<TRet>, "Unknown case");
  }
}

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
                                   uintptr_t sbx_mem_start,
                                   uintptr_t sbx_mem_end,
                                   uintptr_t sbx_stack_loc,
                                   TActualParams &&...args) {
  static_assert(
      std::is_invocable_v<std::remove_pointer_t<TFuncPtr>, TActualParams...>,
      "Calling function with incorrect parameters");

  using TCFuncPtr =
      sepstack_invoker_detail::memberfuncptr_to_cfuncptr_t<TFuncPtr>;

  auto prev_host_stack_ptr = ctx->kstackp;
  auto prev_sbx_stack_ptr = sepstack_invoker_detail::get_stack_register_ref(ctx);
  sepstack_invoker_detail::get_stack_register_ref(ctx) = prev_sbx_stack_ptr != 0 ? prev_sbx_stack_ptr : sbx_stack_loc;

  auto restore_context = sepstack_invoker_detail::make_scope_exit([&]() {
    ctx->kstackp = prev_host_stack_ptr;
    sepstack_invoker_detail::get_stack_register_ref(ctx) = prev_sbx_stack_ptr;
  });

  return sepstack_invoker_detail::invoke_func_on_separate_stack_helper(
      ctx, sbx_mem_start, sbx_mem_end,
      static_cast<TCFuncPtr>(0), std::forward<TActualParams>(args)...);
}

template <typename TFuncPtr>
void invoke_callback_from_separate_stack(LFIContext* ctx,
                                         uintptr_t sbx_mem_start,
                                         uintptr_t sbx_mem_end,
                                         TFuncPtr func_ptr) {
  using TCFuncPtr =
      sepstack_invoker_detail::memberfuncptr_to_cfuncptr_t<TFuncPtr>;
  sepstack_invoker_detail::invoke_callback_from_separate_stack_helper(
      ctx, sbx_mem_start, sbx_mem_end, (TCFuncPtr)func_ptr);
}

#define RLBOX_USE_EXCEPTIONS
#define RLBOX_ENABLE_DEBUG_ASSERTIONS
// #define RLBOX_SINGLE_THREADED_INVOCATIONS
#include "rlbox_lfi_sandbox.hpp" // IWYU pragma: keep

// NOLINTNEXTLINE
#define TestName "rlbox_lfi_sandbox"

// NOLINTNEXTLINE
#define TestType rlbox::rlbox_lfi_sandbox

extern uint8_t glue_lib_lfi_start[];
extern uint8_t glue_lib_lfi_end[];

// NOLINTNEXTLINE
#define CreateSandbox(sandbox) sandbox.create_sandbox(glue_lib_lfi_start, glue_lib_lfi_end)

// NOLINTNEXTLINE
#include "test_sandbox_glue.inc.cpp"


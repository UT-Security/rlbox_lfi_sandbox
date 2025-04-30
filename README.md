[![Tests](https://github.com/PLSysSec/rlbox_lfi_sandbox/actions/workflows/cmake.yml/badge.svg)](https://github.com/PLSysSec/rlbox_lfi_sandbox/actions/workflows/cmake.yml)

# RLBox LFI Sandbox Integration

Integration with RLBox sandboxing API to leverage the sandboxing from the [LFI compiler](link) described in [Lightweight Fault Isolation: Practical, Efficient, and Secure Software Sandboxing](https://dl.acm.org/doi/pdf/10.1145/3620665.3640408)

For details about the RLBox sandboxing APIs, see [here](https://github.com/PLSysSec/rlbox).

## Building/Running the tests

You can build and run the tests using cmake with the following commands.

```bash
cmake -S . -B ./build
cmake --build ./build --parallel
cmake --build ./build --target test
```

## Contributing Code

1. To contribute code, it is recommended you install clang-tidy which the build
uses if available. Install using:

   On Ubuntu:

   ```bash
   sudo apt install clang-tidy
   ```

   On Arch Linux:

   ```bash
   sudo pacman -S clang-tidy
   ```

2. It is recommended you use the dev mode for building during development. This
treat warnings as errors, enables clang-tidy checks, runs address sanitizer etc.
Also, you probably want to use the debug build. To do this, adjust your build
settings as shown below

   ```bash
   cmake -DCMAKE_BUILD_TYPE=Debug -DDEV=ON -S . -B ./build
   ```

3. After making changes to the source, add any new required tests and run all
tests as described earlier.

4. To make sure all code/docs are formatted with, we use clang-format.
Install using:

   On Ubuntu:

   ```bash
   sudo apt install clang-format
   ```

   On Arch Linux:

   ```bash
   sudo pacman -S clang-format
   ```

5. Format code with the format-source target:

   ```bash
   cmake --build ./build --target format-source
   ```

6. Submit the pull request.

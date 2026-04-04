# Justfile for ASTHarbor

# Default recipe
default: build

# Build the project using meson
build:
    meson setup build || true
    meson compile -C build

# Format all C/C++ source files using clang-format
format:
    find src include tests -type f \( -name "*.cpp" -o -name "*.hpp" -o -name "*.h" -o -name "*.c" \) -exec clang-format -i {} +
    echo "Formatting complete."

# Clean the build directory
clean:
    rm -rf build

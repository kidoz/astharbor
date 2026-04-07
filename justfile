# Justfile for ASTHarbor

# Default recipe
default: build

# Build the project using meson
build:
    meson setup build || true
    meson compile -C build

# Run the C++ unit tests
test-cpp:
    meson test -C build --print-errorlogs

# Create or refresh the Python dev environment
python-dev:
    cd python && uv venv --allow-existing .venv
    cd python && uv sync --group dev

# Format the Python package with ruff
python-format:
    cd python && uv venv --allow-existing .venv
    cd python && uv sync --group dev
    cd python && uv run ruff format .

# Lint the Python package with ruff
python-lint:
    cd python && uv venv --allow-existing .venv
    cd python && uv sync --group dev
    cd python && uv run ruff check .

# Type-check the Python package with ty
python-type:
    cd python && uv venv --allow-existing .venv
    cd python && uv sync --group dev
    cd python && uv run ty check

# Run the Python MCP/LSP tests
test-python:
    cd python && uv venv --allow-existing .venv
    cd python && uv sync --group dev
    cd python && uv run pytest -q

# Run the Python quality gates
python-check: python-lint python-type test-python

# Run both C++ and Python checks
test: test-cpp python-check

# Format all C/C++ source files using clang-format
format:
    find src include tests -type f \( -name "*.cpp" -o -name "*.hpp" -o -name "*.h" -o -name "*.c" \) -exec clang-format -i {} +
    echo "Formatting complete."

# Clean the build directory
clean:
    rm -rf build

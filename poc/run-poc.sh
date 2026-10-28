#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${1:?usage: run-poc.sh /path/to/llama.cpp-checkout}" && pwd)"
work="$(mktemp -d)"
trap 'rm -r "$work"' EXIT

echo "checkout: $(git -C "$repo" rev-parse --short HEAD)"

cmake -S "$repo" -B "$work/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=OFF -DGGML_OPENMP=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_SERVER=OFF -DLLAMA_BUILD_TOOLS=OFF > "$work/cmake.log" 2>&1
cmake --build "$work/build" --target ggml -j "$(nproc)" >> "$work/cmake.log" 2>&1

gcc -I "$repo/ggml/include" "$here/gguf_open.c" -o "$work/open" \
  -L "$work/build/bin" -lggml -lggml-base -Wl,-rpath,"$work/build/bin"

python3 "$here/gen_poc.py" > "$work/truncated_ne1_zero.gguf"
python3 "$here/gen_poc_wellformed.py" 4 3 > "$work/control_valid.gguf"
python3 "$here/gen_poc_wellformed.py" 1 0 > "$work/wellformed_ne1_zero.gguf"
python3 "$here/gen_poc_wellformed.py" 1 1 0 > "$work/wellformed_ne2_zero.gguf"

for name in control_valid truncated_ne1_zero wellformed_ne1_zero wellformed_ne2_zero; do
  set +e
  "$work/open" "$work/$name.gguf" > "$work/out.txt" 2>&1
  code=$?
  set -e
  printf '%-22s exit=%-3s %s\n' "$name" "$code" "$(tail -n 1 "$work/out.txt")"
done

cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" .

python3 -m http.server
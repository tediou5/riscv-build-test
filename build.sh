cbindgen --crate riscv-build-test --output riscv_test.h
WEE_ALLOC_STATIC_ARRAY_BACKEND_BYTES=2097152 cargo build -Z build-std=core,alloc --release --target target-gcc.json
# WEE_ALLOC_STATIC_ARRAY_BACKEND_BYTES=2097152 cargo build -Z build-std=core,alloc --release --target arm-unknown-linux-gnueabi
# WEE_ALLOC_STATIC_ARRAY_BACKEND_BYTES=2097152 cargo build -Z build-std=core,alloc --release --target armv7-unknown-linux-gnueabi
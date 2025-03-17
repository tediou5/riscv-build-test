cbindgen --crate riscv-build-test --output riscv_test.h
WEE_ALLOC_STATIC_ARRAY_BACKEND_BYTES=2097152 cargo build --release --target riscv64gc-unknown-none-elf
# WEE_ALLOC_STATIC_ARRAY_BACKEND_BYTES=2097152 cargo build --release --target arm-unknown-linux-gnueabi
# WEE_ALLOC_STATIC_ARRAY_BACKEND_BYTES=2097152 cargo build --release --target armv7-unknown-linux-gnueabi
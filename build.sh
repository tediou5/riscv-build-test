cbindgen --crate riscv-build-test --output riscv_test.h
cargo build --release --target riscv64gc-unknown-none-elf
cargo build --release --target arm-unknown-linux-gnueabi
cargo build --release --target armv7-unknown-linux-gnueabi
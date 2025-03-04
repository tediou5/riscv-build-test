cbindgen --crate riscv-build-test --output riscv_test.h
cargo build --release --target riscv64gc-unknown-none-elf
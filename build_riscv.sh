

configurt_arg=--enable-module-schnorrsig\ --enable-experimental\ --enable-static=yes\ --enable-shared=no\ --host=riscv64-unknown-elf

export CC=riscv64-unknown-elf-gcc
export AR=riscv64-unknown-elf-ar
export LD=riscv64-unknown-elf-ld

./autogen.sh

./configure $configurt_arg
make clean
make bench_schnorrsig

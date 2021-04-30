# WARNING: This script is NOT meant for normal installation, it's dedicated
# to the compilation of all supported targets, from a linux machine.

H1="\n\e[30;104;1m\e[2K\n\e[A" # style first header
H2="\n\e[30;104m\e[1K\n\e[A" # style second header
EH="\e[00m\n\e[2K" # end header

version=$(sed 's/version = "\([0-9.]\{1,\}\(-[a-z]\+\)\?\)"/\1/;t;d' Cargo.toml | head -1)
echo -e "${H1}Compilation of all targets for anolog $version${EH}"
 
# clean previous build
rm -rf build
mkdir build
echo "   build cleaned"

# build the linux version
echo -e "${H2}Compiling the standard linux version${EH}"
cargo build --release
strip target/release/anolog
mkdir build/x86_64-linux/
cp target/release/anolog build/x86_64-linux/

# build a i686 linux version for 32 bits systems
target=i686-unknown-linux-gnu
echo -e "${H2}Compiling the ${target} version${EH}"
cross build --release --target "$target"
mkdir "build/$target"
cp "target/$target/release/anolog" "build/$target"

# build a musl version
echo -e "${H2}Compiling the MUSL version${EH}"
cross build --release --target x86_64-unknown-linux-musl
mkdir build/x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/anolog build/x86_64-unknown-linux-musl

# build the windows version
# use cargo cross
echo -e "${H2}Compiling the Windows version${EH}"
cross build --target x86_64-pc-windows-gnu --release
mkdir build/x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/anolog.exe build/x86_64-pc-windows-gnu/

.PHONY: all debug test clean
all:
	cargo build --release
	mkdir -p output
	cp target/release/aesexe output/aesexe
debug:
	cargo build
	mkdir -p output
	cp target/debug/aesexe output/aesexe
test:
	cargo test
clean:
	cargo clean
	rm -f output/aesexe

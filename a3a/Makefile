all:
	cargo build --release
	mkdir -p ~/.config/radare2/plugins
	cp -f target/release/libsimilarity.so ~/.config/radare2/plugins/

uninstall:
	rm -f ~/.config/radare2/plugins/libsimilarity.so

clean:
	cargo clean

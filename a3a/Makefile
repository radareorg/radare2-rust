SOEXT=$(shell r2 -H LIBEXT)
RHOMEDIR=$(shell r2 -H RHOMEDIR)

all:
	cargo build --release
	mkdir -p $(RHOMEDIR)
	cp -f target/release/libsimilarity.$(SOEXT) $(RHOMEDIR)/plugins

uninstall:
	rm -f $(RHOMEDIR)/plugins/libsimilarity.$(SOEXT)

clean:
	cargo clean

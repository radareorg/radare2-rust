SOEXT=$(shell r2 -HLIBEXT)
USER_PLUGINS=$(shell r2 -HUSER_PLUGINS)

all:
	cargo build --release
	mkdir -p $(USER_PLUGINS)/plugins
	cp -f target/release/libanalrs.$(SOEXT) $(USER_PLUGINS)/plugins

uninstall:
	rm -f $(RHOMEDIR)/plugins/libanalrs.$(SOEXT)

clean:
	cargo clean

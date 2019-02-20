CFLAGS?=
FMT_BIN?=clang-format-7 # fixed version for consistency
FMT_SRC=$(wildcard src/*.h src/*.c)
PSV_SRC=$(wildcard src/psv-*.c)
PSV_BIN=$(PSV_SRC:src/%.c=bin/%)
OUT_DIR=/usr/local/bin
MAN_DIR=/usr/local/share/man
C_FILES=$(shell grep -l '/\*\*' src/psv-*.c)
H_FILES=$(shell grep -l '/\*\*' src/*.h)
MAN1DST=$(C_FILES:src/%.c=docs/%.1)
MAN5DST=$(H_FILES:src/%.h=docs/%.5)
DOC1DST=$(C_FILES:src/%.c=docs/%.1.md)
DOC5DST=$(H_FILES:src/%.h=docs/%.5.md)
ELF_TAG=0.8.13
ELF_TMP=libelf

# list non-file based targets (meaven lifecycle naming):
.PHONY: compile lib validate test package install coverage verify clean

compile: $(PSV_BIN)

deps/lib/libelf.a:
	$(shell mkdir -p $(dir $@) $(ELF_TMP) && wget http://www.mr511.de/software/libelf-$(ELF_TAG).tar.gz -qO- | tar xz --strip-components=1 -C $(ELF_TMP))
	cd $(ELF_TMP) && ./configure --silent && touch po/de && make V=0 --silent all instroot=$(PWD)/deps prefix= install
	rm -rf $(ELF_TMP)

bin/psv-%: src/psv-%.c deps/lib/libelf.a
	$(CC) -std=gnu11 -I deps/include deps/lib/libelf.a -s  $(CFLAGS) -o $@ $^

clean:
	$(RM) $(PSV_BIN) *.gc* coverage *.tar.gz lib

validate: format $(MAN1DST) $(MAN5DST) $(DOC1DST) $(DOC5DST)
	@git diff docs src && exit || echo "\noutdated docs/src!\nplease review with 'git diff' and commit them before re-make $@\n" && exit 1
format: $(FMT_SRC)
	$(FMT_BIN) -i $^
docs/%.5.md: src/%.h
	awk '/\*\// {p=0};{if(p) print $0};/\/\*\*/ {p=1};' $^ > $@
docs/%.1.md: src/%.c
	awk '/\*\// {p=0};{if(p) print $0};/\/\*\*/ {p=1};' $^ > $@
docs/%.5: docs/%.5.md
	echo ".TH $(^:src/%.h=% 5) 5 PSVSDK" > $@; sed 's/^# /.SH /; s/^## /.SS /' < $^ >> $@
docs/%.1: docs/%.1.md
	echo ".TH $(^:src/%.c=% 1) 1 PSVSDK" > $@; sed 's/^# /.SH /; s/^## /.SS /' < $^ >> $@

# Tests
test: compile test_help test_sfo test_vpk
test_help:
	for b in bin/*; do echo testing $$b ... && ./$$b||:; done
test_sfo:
	bin/psv-sfo < tests/vitasdk/base.sfo | xargs bin/psv-sfo | cmp - tests/vitasdk/base.sfo
test_vpk:
	! bin/psv-vpk < bin/psv-vpk > /dev/null
	bin/psv-vpk < tests/vitasdk/main_deps2.self > /tmp/stdin.vpk
	bin/psv-vpk tests/vitasdk/main_deps2.self:eboot.bin > /tmp/arg.vpk
	cmp /tmp/stdin.vpk /tmp/arg.vpk
	unzip -od/tmp /tmp/stdin.vpk &>/dev/null
	bin/psv-sfo < /tmp/sce_sys/param.sfo

test_velf:
	bin/psv-velf < tests/vitasdk/main_deps.elf     | cmp tests/vitasdk/main_deps.velf
	bin/psv-velf < tests/vitasdk/main_no_deps.elf  | cmp tests/vitasdk/main_no_deps.velf
test_self:
	bin/psv-self < tests/vitasdk/main_deps.velf    | cmp tests/vitasdk/main_deps.self
	bin/psv-self < tests/vitasdk/main_no_deps.velf | cmp tests/vitasdk/main_no_deps.self
test_module:
	psv-cc <<< "TODO:{U,K} App : vector maths, load {U,K} module, call {U,K} exports"

package: compile lib
	tar -zcf psvsdk.tar.gz docs bin #headers samples

install: compile lib
	cp bin/* $(OUT_DIR)
	mkdir -p $(MAN_DIR)/man5/ $(MAN_DIR)/man1/
	cp docs/*.5 $(MAN_DIR)/man5/
	cp docs/*.1 $(MAN_DIR)/man1/
install_usr: compile lib
	[ ! -z "$(DESTDIR)" ] # no writable PATH entries for binaries retry with sudo
	echo cp bin/* $(lastword $(DESTDIR))
	[ ! -z "$(MAN_DIR)" ] # no writable PATH entries for man pages retry with sudo
	echo cp docs/man* $(lastword $(MAN_DIR))

coverage:
	make clean CFLAGS="-O0 --coverage" test
	[ -z "${CI}" ] && lcov --capture --directory . --output-file $@ || curl -sL codecov.io/bash|bash
	

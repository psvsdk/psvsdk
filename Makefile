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
.PHONY: compile lib docs validate test package install coverage verify clean

compile: $(PSV_BIN)

deps/lib/libelf.a:
	$(shell mkdir -p $(dir $@) $(ELF_TMP) && wget https://github.com/Distrotech/libelf/archive/master.tar.gz -qO- | tar xz --strip-components=1 -C $(ELF_TMP))
	cd $(ELF_TMP) && ./configure --silent && touch po/de && make V=0 --silent all instroot=$(PWD)/deps prefix= install
	rm -rf $(ELF_TMP)

bin/psv-%: src/psv-%.c deps/lib/libelf.a
	cat docs/$(notdir $@).1.md 2>&1 | xxd -i -c 99999 | xargs -I% $(CC) -DUSAGE='(char[]){0xa,%,0}' -std=gnu11 -I deps/include deps/lib/libelf.a -s $(CFLAGS) -o $@ $^

clean:
	$(RM) $(PSV_BIN) *.gc* coverage *.tar.gz lib

docs: $(MAN1DST) $(MAN5DST) $(DOC1DST) $(DOC5DST)
docs/%.5.md: src/%.h
	awk '/\*\// {p=0};{if(p) print $0};/\/\*\*/ {p=1};' $^ > $@
docs/%.1.md: src/%.c
	awk '/\*\// {p=0};{if(p) print $0};/\/\*\*/ {p=1};' $^ > $@
docs/%.5: docs/%.5.md
	echo ".TH $(^:src/%.h=% 5) 5 PSVSDK" > $@; sed 's/^# /.SH /; s/^## /.SS /' < $^ >> $@
docs/%.1: docs/%.1.md
	echo ".TH $(^:src/%.c=% 1) 1 PSVSDK" > $@; sed 's/^# /.SH /; s/^## /.SS /' < $^ >> $@

validate: format docs
	@git diff docs src && exit || echo "\noutdated docs/src!\nplease review with 'git diff' and commit them before re-make $@\n" && exit 1
format: $(FMT_SRC)
	$(FMT_BIN) -i $^

test: compile test_help test_sfo test_self test_vpk test_db test_export
test_help:
	for b in bin/*; do echo testing $$b ... && ./$$b||:; done
test_sfo:
	bin/psv-sfo < tests/base.sfo | xargs bin/psv-sfo | cmp - tests/base.sfo
	bin/psv-sfo __VER:2*8/16~8@2-1="_0x000" | bin/psv-sfo
	! bin/psv-sfo TEST=0x42
	! bin/psv-sfo > /dev/null
test_vpk:
	! bin/psv-vpk < bin/psv-vpk > /dev/null
	bin/psv-vpk bin:assets < tests/main.self > /tmp/stdin.vpk
	bin/psv-vpk bin:assets tests/main.self:eboot.bin > /tmp/arg.vpk
	cmp /tmp/stdin.vpk /tmp/arg.vpk
	! unzip -od/tmp /tmp/stdin.vpk
	bin/psv-sfo < /tmp/sce_sys/param.sfo
test_self:
	bin/psv-self --type=1 --selftype=8 < tests/main.velf    | cmp tests/main.self
	! bin/psv-self --help
test_db:
	bin/psv-db < tests/360.yml
test_export:
	bin/psv-export
test_velf:
	bin/psv-velf < tests/main.elf     | cmp tests/main.velf
test_module:
	psv-gcc <<< "TODO:{U,K} App : vector maths, load {U,K} module, call {U,K} exports"

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

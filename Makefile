.PHONY: clean
LDFLAGS = -lnet -lpcap -lpthread
CFLAGS = -Wall

tcpkill: pcaputil.o tcpkill.c
	${CC} ${CFLAGS} -o $@ $^ ${LDFLAGS}

clean:
	rm -f pcaputil.o tcpkill
test:
	python3 tests/test_basic.py

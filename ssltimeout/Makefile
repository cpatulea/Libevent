CXXFLAGS = -I../include -O0 -g -ggdb
LDFLAGS = ../.libs/libevent.a ../.libs/libevent_openssl.a -lssl -lcrypto -lrt

all: ssltimeout
.PHONY: clean all
clean:
	rm -f ssltimeout main.o

ssltimeout: main.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

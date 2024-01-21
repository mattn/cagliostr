SRCS = \
	main.cxx \
	deps/matheus28-ws28/src/Server.cpp \
	deps/matheus28-ws28/src/Client.cpp \
	deps/matheus28-ws28/src/base64.cpp

OBJS = $(subst .cc,.o,$(subst .cxx,.o,$(subst .cpp,.o,$(SRCS))))

CXXFLAGS = -std=c++17 -I deps/matheus28-ws28/src -I deps/dcdpr-libbech32/include -I deps/nlohmann-json/include -I deps/secp256k1/include
LIBS = -luv -lcrypto -lssl -lsecp256k1
LIBDIRS = -L deps/secp256k1/build/src -L deps/dcdpr-libbech32/build/libbech32
TARGET = cagliostr
ifeq ($(OS),Windows_NT)
TARGET := $(TARGET).exe
endif

.SUFFIXES: .cpp .cc .cxx .o

all : $(TARGET)

deps-build:
	rm -rf deps/dcdpr-libbech32/build
	mkdir -p deps/dcdpr-libbech32/build
	cmake -S deps/dcdpr-libbech32 -B deps/dcdpr-libbech32/build
	make -C deps/dcdpr-libbech32/build
	rm -rf deps/secp256k1/build
	mkdir -p deps/secp256k1/build
	cmake -S deps/secp256k1 -B deps/secp256k1/build
	make -C deps/secp256k1/build

$(TARGET) : deps-build $(OBJS)
	g++ -o $@ $(OBJS) $(LIBDIRS) $(LIBS)

.cxx.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

.cpp.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

.cc.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

clean :
	rm -f *.o $(TARGET)

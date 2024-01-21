SRCS = \
	main.cxx \
	../ws28/src/Server.cpp \
	../ws28/src/Client.cpp \
	../ws28/src/base64.cpp

OBJS = $(subst .cc,.o,$(subst .cxx,.o,$(subst .cpp,.o,$(SRCS))))

CXXFLAGS = -std=c++17 -I ../ws28/src -I ../libbech32/include
LIBS = -luv -lcrypto -lssl -lsecp256k1
TARGET = cagliostr
ifeq ($(OS),Windows_NT)
TARGET := $(TARGET).exe
endif

.SUFFIXES: .cpp .cc .cxx .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	g++ -o $@ $(OBJS) $(LIBS)

.cxx.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

.cpp.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

.cc.o :
	g++ -c $(CXXFLAGS) -I. $< -o $@

clean :
	rm -f *.o $(TARGET)

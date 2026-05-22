CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
INCLUDES = -Iinclude
SRCS = src/main.cpp src/chacha20.cpp src/Keys.cpp src/Server.cpp
TARGET = output/aesexe
LDLIBS = -lssl -lcrypto

.PHONY: all debug clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(SRCS) $(INCLUDES) $(CXXFLAGS) -o $(TARGET) $(LDLIBS)

debug: CXXFLAGS += -g -DDEBUG
debug: $(SRCS)
	$(CXX) $(SRCS) $(INCLUDES) $(CXXFLAGS) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)

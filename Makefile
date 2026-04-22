CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
INCLUDES = -Iinclude
SRCS = src/main.cpp src/chacha20.cpp src/Keys.cpp
TARGET = output/aesexe

.PHONY: all debug clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(SRCS) $(INCLUDES) $(CXXFLAGS) -o $(TARGET)

debug: CXXFLAGS += -g -DDEBUG
debug: $(SRCS)
	$(CXX) $(SRCS) $(INCLUDES) $(CXXFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

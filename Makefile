# Compiler and flags
CC = g++
CFLAGS = -Wall -std=c++14 -g -fconcepts -Wextra -Werror
LDFLAGS = -lm -lpcap

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = .

# Source and object files
SRCS = $(wildcard $(SRCDIR)/*.cpp)
OBJS = $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRCS))

# Binaries
TARGET = $(BINDIR)/dns-monitor
CLIENT = ./test/udp-client

# Default target
all: $(TARGET) $(CLIENT)

# Link dns-monitor executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile object files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp $(INCDIR)/*.h
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build the UDP client for testing
$(CLIENT): test/udp-client.cpp
	$(CC) $(CFLAGS) -o $(CLIENT) test/udp-client.cpp $(LDFLAGS)

# Clean target to remove compiled objects and binaries
clean:
	rm -rf $(OBJDIR) $(TARGET) $(CLIENT)

# Run the DNS monitor (requires sudo for privileged port)
run: $(TARGET)
	./dns-monitor

# Run tests by launching the DNS monitor and using 'dig' as a subprocess
tests: 
	./dns-monitor & nslookup -port=1053 seznam.cz 127.0.0.1
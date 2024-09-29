# Compiler and flags
CC = g++
CFLAGS = -Wall -std=c++14 -g -fconcepts -Wextra -Werror
LDFLAGS = -lm

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
	sudo ./dns-monitor

# Run tests by launching the DNS monitor and using 'dig' as a subprocess
tests:
	dig @127.0.0.1 -p 1053 example.com
# Compiler and flags
CC = g++
CFLAGS = -Wall -std=c++14 -g -fconcepts -Wextra -Werror
LDFLAGS = -lm -lpcap

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
DOCDIR = docs
TESTDIR = test
FILES = .
BINDIR = .

# Source and object files
SRCS = $(wildcard $(SRCDIR)/*.cpp)
OBJS = $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRCS))

# Binaries
TARGET = $(BINDIR)/dns-monitor

# Default target
all: $(TARGET) $(CLIENT)

# Link dns-monitor executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile object files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp $(INCDIR)/*.h
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target to remove compiled objects and binaries
clean:
	rm -rf $(OBJDIR) $(TARGET) $(CLIENT) $(FILES)/domain.txt $(FILES)/translation.txt $(DOCDIR) $(TESTDIR)/A/translation.txt $(TESTDIR)/AAAA/translation.txt $(TESTDIR)/CNAME/translation.txt  $(TESTDIR)/BIG/translation.txt $(TESTDIR)/MX/translation.txt $(TESTDIR)/NS/translation.txt $(TESTDIR)/SOA/translation.txt 


# Run the DNS monitor (requires sudo for privileged port)
run: $(TARGET)
	sudo ./dns-monitor -p test/test1.pcap -d domain.txt -t translation.txt -v

# Run tests by launching the DNS monitor and using 'dig' as a subprocess
tests: 
	cd test && python3 test.py

tests_clean:
	rm -rf $(TESTDIR)/A/translation.txt $(TESTDIR)/AAAA/translation.txt $(TESTDIR)/CNAME/translation.txt $(TESTDIR)/MX/translation.txt $(TESTDIR)/NS/translation.txt $(TESTDIR)/SOA/translation.txt $(TESTDIR)/BIG/translation.txt

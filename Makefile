# Makefile for Supabase RLS Scanner
# Supports Linux, macOS, and Windows (via WSL or Git Bash)

# Project configuration
PROJECT_NAME := supabase-rls-scanner
VERSION := 1.0.0
JAR_NAME := $(PROJECT_NAME)-$(VERSION).jar
BUILD_DIR := build/libs
GRADLE_WRAPPER := ./gradlew

# Detect OS
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    GRADLE_WRAPPER := gradlew.bat
    JAVA_HOME_CMD := where java
    RM := del /Q
    RM_RF := rmdir /S /Q
    MKDIR := mkdir
    SEP := \\
else
    DETECTED_OS := $(shell uname -s)
    JAVA_HOME_CMD := which java
    RM := rm -f
    RM_RF := rm -rf
    MKDIR := mkdir -p
    SEP := /
endif

# Java version detection
JAVA_VERSION := $(shell java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1)
REQUIRED_JAVA_VERSION := 21

# Colors for output (works on Linux/macOS, limited on Windows)
ifndef NO_COLOR
    GREEN := \033[0;32m
    YELLOW := \033[0;33m
    RED := \033[0;31m
    NC := \033[0m
else
    GREEN :=
    YELLOW :=
    RED :=
    NC :=
endif

.PHONY: all build clean test check-java help install-deps info

# Default target
all: check-java build

# Build the JAR file
build: check-java
	@echo "$(GREEN)Building $(PROJECT_NAME) for $(DETECTED_OS)...$(NC)"
ifeq ($(DETECTED_OS),Darwin)
	@echo "$(YELLOW)Using Java 21 for macOS build...$(NC)"
	@export JAVA_HOME=$$(/usr/libexec/java_home -v 21 2>/dev/null || echo /usr/lib/jvm/java-21) && \
		$(GRADLE_WRAPPER) clean build --no-daemon
else ifeq ($(DETECTED_OS),Linux)
	@echo "$(YELLOW)Building on Linux...$(NC)"
	@export JAVA_HOME=$$(dirname $$(dirname $$(readlink -f $$(which java)))) && \
		$(GRADLE_WRAPPER) clean build --no-daemon
else
	@echo "$(YELLOW)Building on Windows...$(NC)"
	@$(GRADLE_WRAPPER) clean build --no-daemon
endif
	@echo "$(GREEN)Build complete! JAR location: $(BUILD_DIR)$(SEP)$(JAR_NAME)$(NC)"
	@ls -lh $(BUILD_DIR)/$(JAR_NAME) 2>/dev/null || dir $(BUILD_DIR)$(SEP)$(JAR_NAME)

# Quick build without cleaning
quick-build: check-java
	@echo "$(GREEN)Quick building $(PROJECT_NAME)...$(NC)"
ifeq ($(DETECTED_OS),Darwin)
	@export JAVA_HOME=$$(/usr/libexec/java_home -v 21 2>/dev/null || echo /usr/lib/jvm/java-21) && \
		$(GRADLE_WRAPPER) build --no-daemon
else
	@$(GRADLE_WRAPPER) build --no-daemon
endif
	@echo "$(GREEN)Build complete!$(NC)"

# Clean build artifacts
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@$(GRADLE_WRAPPER) clean || true
	@echo "$(GREEN)Clean complete!$(NC)"

# Run tests
test: check-java
	@echo "$(GREEN)Running tests...$(NC)"
	@$(GRADLE_WRAPPER) test --no-daemon
	@echo "$(GREEN)Tests complete!$(NC)"

# Check Java version
check-java:
	@echo "$(YELLOW)Checking Java version...$(NC)"
	@java -version 2>&1 | head -n 3
ifeq ($(shell test $(JAVA_VERSION) -ge $(REQUIRED_JAVA_VERSION); echo $$?),1)
	@echo "$(RED)Error: Java $(REQUIRED_JAVA_VERSION) or higher is required. Found Java $(JAVA_VERSION)$(NC)"
	@echo "$(YELLOW)Please install Java $(REQUIRED_JAVA_VERSION) or set JAVA_HOME to point to Java $(REQUIRED_JAVA_VERSION)+$(NC)"
	@exit 1
else
	@echo "$(GREEN)Java version OK ($(JAVA_VERSION))$(NC)"
endif

# Install dependencies (download Gradle wrapper if needed)
install-deps:
	@echo "$(GREEN)Installing dependencies...$(NC)"
ifeq ($(wildcard $(GRADLE_WRAPPER)),)
	@echo "$(YELLOW)Gradle wrapper not found. Please run: gradle wrapper$(NC)"
else
	@echo "$(GREEN)Gradle wrapper found!$(NC)"
endif

# Show project information
info:
	@echo "$(GREEN)Project Information:$(NC)"
	@echo "  Name: $(PROJECT_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  JAR: $(JAR_NAME)"
	@echo "  Build Dir: $(BUILD_DIR)"
	@echo "  OS: $(DETECTED_OS)"
	@echo "  Java Version: $(JAVA_VERSION)"
	@echo "  Gradle: $(GRADLE_WRAPPER)"

# Verify the built JAR
verify: build
	@echo "$(GREEN)Verifying JAR contents...$(NC)"
	@jar tf $(BUILD_DIR)/$(JAR_NAME) | grep -E "(PassiveScanner|ScannerPanel|SupabaseRlsScanner)\.class" || \
		echo "$(RED)Warning: Core classes not found in JAR$(NC)"
	@echo "$(GREEN)Verification complete!$(NC)"

# Package for distribution
package: build
	@echo "$(GREEN)Creating distribution package...$(NC)"
	@$(MKDIR) dist 2>/dev/null || true
	@cp $(BUILD_DIR)/$(JAR_NAME) dist/
	@cp README.md dist/ 2>/dev/null || echo "No README.md found"
	@echo "$(GREEN)Package created in dist/$(NC)"

# Help target
help:
	@echo "$(GREEN)Supabase RLS Scanner - Makefile Help$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@echo "  make              - Build the project (default)"
	@echo "  make build        - Clean and build the JAR file"
	@echo "  make quick-build  - Build without cleaning"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make test         - Run tests"
	@echo "  make check-java   - Verify Java version"
	@echo "  make verify       - Build and verify JAR contents"
	@echo "  make package      - Create distribution package"
	@echo "  make info         - Show project information"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "$(YELLOW)Platform Support:$(NC)"
	@echo "  - Linux (tested)"
	@echo "  - macOS (tested)"
	@echo "  - Windows (via Git Bash or WSL)"
	@echo ""
	@echo "$(YELLOW)Requirements:$(NC)"
	@echo "  - Java $(REQUIRED_JAVA_VERSION) or higher"
	@echo "  - Gradle wrapper (included)"


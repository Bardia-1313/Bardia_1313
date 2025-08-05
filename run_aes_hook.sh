#!/bin/bash

# AES Hook Frida Script Runner
# اسکریپت اجرای فریدا برای هوک AES

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_NAME="aes_hook_frida.js"
DEFAULT_PACKAGE="com.example.targetapp"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  AES Hook Frida Script Runner${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if frida is installed
    if ! command -v frida &> /dev/null; then
        print_error "Frida is not installed. Please install it first:"
        echo "  pip install frida-tools"
        exit 1
    fi
    
    # Check if script exists
    if [ ! -f "$SCRIPT_NAME" ]; then
        print_error "Script file '$SCRIPT_NAME' not found in current directory"
        exit 1
    fi
    
    # Check if device is connected
    if ! frida-ps -U &> /dev/null; then
        print_error "No USB device connected or Frida server not running on device"
        echo "  Make sure your device is connected and Frida server is running"
        exit 1
    fi
    
    print_status "Prerequisites check passed"
}

# Function to list available processes
list_processes() {
    print_status "Available processes:"
    echo ""
    frida-ps -U | head -20
    echo ""
    print_warning "Showing first 20 processes. Use 'frida-ps -U' for full list"
}

# Function to attach to running process
attach_to_process() {
    local process_name=$1
    
    if [ -z "$process_name" ]; then
        print_status "No process specified, showing available processes..."
        list_processes
        echo -n "Enter process name or PID: "
        read process_name
    fi
    
    if [ -z "$process_name" ]; then
        print_error "No process specified"
        exit 1
    fi
    
    print_status "Attaching to process: $process_name"
    frida -U -l "$SCRIPT_NAME" -f "$process_name"
}

# Function to spawn and attach
spawn_and_attach() {
    local package_name=$1
    
    if [ -z "$package_name" ]; then
        echo -n "Enter package name (default: $DEFAULT_PACKAGE): "
        read package_name
        package_name=${package_name:-$DEFAULT_PACKAGE}
    fi
    
    print_status "Spawning and attaching to package: $package_name"
    frida -U -l "$SCRIPT_NAME" --no-pause -f "$package_name"
}

# Function to attach by PID
attach_by_pid() {
    local pid=$1
    
    if [ -z "$pid" ]; then
        echo -n "Enter process PID: "
        read pid
    fi
    
    if [ -z "$pid" ]; then
        print_error "No PID specified"
        exit 1
    fi
    
    print_status "Attaching to PID: $pid"
    frida -U -l "$SCRIPT_NAME" -p "$pid"
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -a, --attach PROCESS    Attach to running process by name"
    echo "  -p, --pid PID          Attach to process by PID"
    echo "  -s, --spawn PACKAGE    Spawn and attach to package"
    echo "  -l, --list             List available processes"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -a com.example.app"
    echo "  $0 -p 12345"
    echo "  $0 -s com.example.encryptionapp"
    echo "  $0 -l"
    echo ""
    echo "Interactive mode:"
    echo "  $0                    Run in interactive mode"
}

# Function to run interactive mode
interactive_mode() {
    print_header
    
    while true; do
        echo ""
        echo "Choose an option:"
        echo "  1) Attach to running process"
        echo "  2) Spawn and attach to package"
        echo "  3) Attach by PID"
        echo "  4) List available processes"
        echo "  5) Show help"
        echo "  6) Exit"
        echo ""
        echo -n "Enter your choice (1-6): "
        read choice
        
        case $choice in
            1)
                echo ""
                attach_to_process
                break
                ;;
            2)
                echo ""
                spawn_and_attach
                break
                ;;
            3)
                echo ""
                attach_by_pid
                break
                ;;
            4)
                echo ""
                list_processes
                ;;
            5)
                echo ""
                show_help
                ;;
            6)
                print_status "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please enter a number between 1 and 6."
                ;;
        esac
    done
}

# Main function
main() {
    # Parse command line arguments
    case "${1:-}" in
        -a|--attach)
            check_prerequisites
            attach_to_process "$2"
            ;;
        -p|--pid)
            check_prerequisites
            attach_by_pid "$2"
            ;;
        -s|--spawn)
            check_prerequisites
            spawn_and_attach "$2"
            ;;
        -l|--list)
            check_prerequisites
            list_processes
            ;;
        -h|--help)
            show_help
            ;;
        "")
            check_prerequisites
            interactive_mode
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
#!/bin/bash

# AES Hook Frida Script Runner
# اسکریپت اجرای هوک AES فریدا

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check if Frida is installed
check_frida() {
    if ! command -v frida &> /dev/null; then
        print_error "Frida is not installed. Please install it first:"
        echo "pip install frida-tools"
        exit 1
    fi
    print_status "Frida is installed"
}

# Check if ADB is available
check_adb() {
    if ! command -v adb &> /dev/null; then
        print_warning "ADB is not installed. Make sure your device is connected via USB."
    else
        print_status "ADB is available"
    fi
}

# Check if device is connected
check_device() {
    if command -v adb &> /dev/null; then
        if adb devices | grep -q "device$"; then
            print_status "Android device is connected"
        else
            print_warning "No Android device connected via USB"
        fi
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -f, --app <package_name>    Launch new app with package name"
    echo "  -n, --name <app_name>       Attach to running app by name"
    echo "  -p, --pid <process_id>      Attach to process by PID"
    echo "  -s, --script <script_file>  Use custom script file (default: aes_hook_frida.js)"
    echo "  -h, --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -f com.example.app"
    echo "  $0 -n \"Example App\""
    echo "  $0 -p 1234"
    echo "  $0 -f com.example.app -s custom_script.js"
}

# Main function
main() {
    print_header "AES Hook Frida Script Runner"
    
    # Parse command line arguments
    APP_PACKAGE=""
    APP_NAME=""
    PROCESS_PID=""
    SCRIPT_FILE="aes_hook_frida.js"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--app)
                APP_PACKAGE="$2"
                shift 2
                ;;
            -n|--name)
                APP_NAME="$2"
                shift 2
                ;;
            -p|--pid)
                PROCESS_PID="$2"
                shift 2
                ;;
            -s|--script)
                SCRIPT_FILE="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check if script file exists
    if [[ ! -f "$SCRIPT_FILE" ]]; then
        print_error "Script file not found: $SCRIPT_FILE"
        exit 1
    fi
    
    # Check dependencies
    check_frida
    check_adb
    check_device
    
    # Build Frida command
    FRIDA_CMD="frida -U"
    
    if [[ -n "$APP_PACKAGE" ]]; then
        FRIDA_CMD="$FRIDA_CMD -f $APP_PACKAGE"
        print_status "Will launch app: $APP_PACKAGE"
    elif [[ -n "$APP_NAME" ]]; then
        FRIDA_CMD="$FRIDA_CMD -n \"$APP_NAME\""
        print_status "Will attach to app: $APP_NAME"
    elif [[ -n "$PROCESS_PID" ]]; then
        FRIDA_CMD="$FRIDA_CMD -p $PROCESS_PID"
        print_status "Will attach to process: $PROCESS_PID"
    else
        print_error "No target specified. Use -f, -n, or -p option."
        show_usage
        exit 1
    fi
    
    FRIDA_CMD="$FRIDA_CMD -l $SCRIPT_FILE --no-pause"
    
    print_status "Running Frida command:"
    echo "$FRIDA_CMD"
    echo ""
    
    # Ask for confirmation
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Operation cancelled"
        exit 0
    fi
    
    # Run Frida
    print_header "Starting Frida Hook"
    eval $FRIDA_CMD
}

# Run main function with all arguments
main "$@"
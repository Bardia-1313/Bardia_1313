#!/bin/bash
# Frida AES Hook Runner Script
# اسکریپت اجرای خودکار هوک‌های فریدا

echo "=== Frida AES Hook Runner ==="
echo "اسکریپت اجرای هوک‌های AES فریدا"
echo ""

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

print_command() {
    echo -e "${BLUE}[CMD]${NC} $1"
}

# Check if Frida is installed
if ! command -v frida &> /dev/null; then
    print_error "Frida not found! Please install it first:"
    echo "pip install frida-tools"
    exit 1
fi

print_status "Frida version: $(frida --version)"

# Available scripts
SCRIPTS=(
    "frida_aes_hook.js:جامع - General AES functions"
    "frida_go_aes_hook.js:تخصصی Go - Go crypto functions"
    "simple_aes_hook.js:ساده - Simple & lightweight"
)

echo ""
echo "Available Frida scripts / اسکریپت‌های موجود:"
for i in "${!SCRIPTS[@]}"; do
    IFS=':' read -r script desc <<< "${SCRIPTS[$i]}"
    echo "$((i+1)). $script - $desc"
done

echo ""
echo "Usage modes / حالت‌های استفاده:"
echo "1. Android app (-U)"
echo "2. Desktop process (-p PID)"
echo "3. Process by name (-n name)"
echo "4. Spawn mode (-f)"

echo ""
read -p "Select script number (1-${#SCRIPTS[@]}) / شماره اسکریپت: " script_choice
read -p "Select mode (1-4) / حالت: " mode_choice

# Validate script choice
if [[ $script_choice -lt 1 || $script_choice -gt ${#SCRIPTS[@]} ]]; then
    print_error "Invalid script choice!"
    exit 1
fi

# Get selected script
IFS=':' read -r selected_script desc <<< "${SCRIPTS[$((script_choice-1))]}"

if [[ ! -f "$selected_script" ]]; then
    print_error "Script file not found: $selected_script"
    exit 1
fi

print_status "Selected script: $selected_script"

# Build Frida command based on mode
case $mode_choice in
    1)
        echo ""
        print_status "Android mode selected"
        frida-ps -U | head -20
        echo ""
        read -p "Enter app package name / نام بسته اپلیکیشن: " package_name
        
        if [[ -z "$package_name" ]]; then
            print_error "Package name cannot be empty!"
            exit 1
        fi
        
        cmd="frida -U -f $package_name -l $selected_script --no-pause"
        ;;
    2)
        echo ""
        print_status "Desktop PID mode selected"
        ps aux | grep -E "(go|crypto|jni)" | head -10
        echo ""
        read -p "Enter process PID / شناسه پروسه: " pid
        
        if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
            print_error "Invalid PID!"
            exit 1
        fi
        
        cmd="frida -p $pid -l $selected_script"
        ;;
    3)
        echo ""
        print_status "Process name mode selected"
        ps aux | grep -E "(go|crypto|jni)" | head -10
        echo ""
        read -p "Enter process name / نام پروسه: " process_name
        
        if [[ -z "$process_name" ]]; then
            print_error "Process name cannot be empty!"
            exit 1
        fi
        
        cmd="frida -n \"$process_name\" -l $selected_script"
        ;;
    4)
        echo ""
        print_status "Spawn mode selected"
        read -p "Enter target application / اپلیکیشن هدف: " target_app
        
        if [[ -z "$target_app" ]]; then
            print_error "Target application cannot be empty!"
            exit 1
        fi
        
        cmd="frida -U -f $target_app -l $selected_script"
        ;;
    *)
        print_error "Invalid mode choice!"
        exit 1
        ;;
esac

# Ask for output options
echo ""
echo "Output options / گزینه‌های خروجی:"
echo "1. Console only"
echo "2. Save to file"
echo "3. Both console and file"

read -p "Select output option (1-3): " output_choice

case $output_choice in
    1)
        final_cmd="$cmd"
        ;;
    2)
        log_file="aes_keys_$(date +%Y%m%d_%H%M%S).log"
        final_cmd="$cmd > $log_file 2>&1"
        print_status "Output will be saved to: $log_file"
        ;;
    3)
        log_file="aes_keys_$(date +%Y%m%d_%H%M%S).log"
        final_cmd="$cmd 2>&1 | tee $log_file"
        print_status "Output will be shown and saved to: $log_file"
        ;;
    *)
        final_cmd="$cmd"
        print_warning "Invalid output choice, using console only"
        ;;
esac

echo ""
print_command "$final_cmd"
echo ""
read -p "Execute command? (y/N) / اجرای دستور؟ " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Executing Frida hook..."
    print_status "Use Ctrl+C to stop"
    echo ""
    
    eval $final_cmd
    
    echo ""
    print_status "Frida hook execution completed"
    
    if [[ -n "$log_file" && -f "$log_file" ]]; then
        print_status "Log file created: $log_file"
        echo "Key extraction summary:"
        grep -E "(AES_KEY|CIPHER_IV|KEY/IV)" "$log_file" | head -10
    fi
else
    print_status "Command execution cancelled"
fi

echo ""
print_status "Done!"
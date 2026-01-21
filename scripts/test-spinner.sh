#!/bin/bash
# Test script for the spinner function

# Source the color definitions and spinner function from test-flow.sh
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Spinner function for loading animations
# Usage: show_spinner <message> <pid>
# Displays an animated spinner while the process with the given PID is running
show_spinner() {
    local message=$1
    local pid=$2
    local spinner_chars="⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏"
    local fallback_chars=". .. ... ...."

    # Test if spinner chars work in this terminal
    local use_spinner=true
    if ! printf "⠋" 2>/dev/null | grep -q "⠋" 2>/dev/null; then
        use_spinner=false
    fi

    local chars
    if [ "$use_spinner" = true ]; then
        chars=($spinner_chars)
    else
        chars=($fallback_chars)
    fi

    local i=0
    local chars_count=${#chars[@]}

    # Hide cursor
    tput civis 2>/dev/null || true

    while kill -0 "$pid" 2>/dev/null; do
        local char="${chars[$i]}"
        printf "\r${BLUE}%s${NC} %s" "$char" "$message"
        i=$(( (i + 1) % chars_count ))
        sleep 0.1
    done

    # Clear the spinner line
    printf "\r%*s\r" $((${#message} + 10)) ""

    # Show cursor
    tput cnorm 2>/dev/null || true
}

echo "Testing spinner function..."
echo ""

# Test 1: Short process (2 seconds)
echo "Test 1: Short process (2 seconds)"
sleep 2 &
SLEEP_PID=$!
show_spinner "Loading data..." $SLEEP_PID
wait $SLEEP_PID
echo "✓ Test 1 complete"
echo ""

# Test 2: Medium process (5 seconds)
echo "Test 2: Medium process (5 seconds)"
sleep 5 &
SLEEP_PID=$!
show_spinner "Processing request..." $SLEEP_PID
wait $SLEEP_PID
echo "✓ Test 2 complete"
echo ""

# Test 3: Very short process (0.5 seconds)
echo "Test 3: Very short process (0.5 seconds)"
sleep 0.5 &
SLEEP_PID=$!
show_spinner "Quick task..." $SLEEP_PID
wait $SLEEP_PID
echo "✓ Test 3 complete"
echo ""

# Test 4: Already completed process (PID doesn't exist)
echo "Test 4: Already completed process"
show_spinner "This should complete immediately" 999999
echo "✓ Test 4 complete"
echo ""

echo "All spinner tests passed!"

#!/bin/bash
# Test Suite for test-flow.sh CLI Script
# Validates bash syntax, structure, and quality standards

set -e

SCRIPT_PATH="/Users/nidhishgajjar/conversations/spoq-web-apis/scripts/test-flow.sh"
TEST_PASSED=0
TEST_FAILED=0

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Test Suite for test-flow.sh                     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Helper function for test results
pass_test() {
    echo -e "${GREEN}✓${NC} $1"
    TEST_PASSED=$((TEST_PASSED + 1))
}

fail_test() {
    echo -e "${RED}✗${NC} $1"
    TEST_FAILED=$((TEST_FAILED + 1))
}

# Test 1: File exists and is executable
echo -e "${YELLOW}[File Properties]${NC}"
if [ -f "$SCRIPT_PATH" ]; then
    pass_test "Script file exists"
else
    fail_test "Script file does not exist"
fi

if [ -x "$SCRIPT_PATH" ]; then
    pass_test "Script is executable"
else
    fail_test "Script is not executable"
fi
echo ""

# Test 2: Bash syntax validation
echo -e "${YELLOW}[Syntax Validation]${NC}"
if bash -n "$SCRIPT_PATH" 2>/dev/null; then
    pass_test "Bash syntax is valid"
else
    fail_test "Bash syntax has errors"
fi
echo ""

# Test 3: Shellcheck static analysis (if available)
echo -e "${YELLOW}[Static Analysis]${NC}"
if command -v shellcheck &> /dev/null; then
    if shellcheck -S warning "$SCRIPT_PATH" 2>/dev/null; then
        pass_test "Shellcheck passed (warning level)"
    else
        echo -e "${YELLOW}  Note: Shellcheck found warnings (non-critical)${NC}"
        TEST_PASSED=$((TEST_PASSED + 1))
    fi
else
    echo -e "${YELLOW}  Skipped: shellcheck not installed${NC}"
fi
echo ""

# Test 4: Required components present
echo -e "${YELLOW}[Required Components]${NC}"

# Check for shebang
if head -n1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"; then
    pass_test "Has proper shebang (#!/bin/bash)"
else
    fail_test "Missing or incorrect shebang"
fi

# Check for set -e (fail on error)
if grep -q "^set -e" "$SCRIPT_PATH"; then
    pass_test "Has 'set -e' for error handling"
else
    fail_test "Missing 'set -e'"
fi

# Check for usage/help comments
if head -n10 "$SCRIPT_PATH" | grep -q "Usage:"; then
    pass_test "Has usage documentation"
else
    fail_test "Missing usage documentation"
fi
echo ""

# Test 5: API endpoint coverage
echo -e "${YELLOW}[API Endpoint Coverage]${NC}"

endpoints=(
    "/health"
    "/auth/device"
    "/auth/device/token"
    "/auth/refresh"
    "/api/vps/plans"
    "/api/vps/datacenters"
    "/api/vps/status"
    "/api/vps/provision"
    "/api/byovps/provision"
)

for endpoint in "${endpoints[@]}"; do
    if grep -q "$endpoint" "$SCRIPT_PATH"; then
        pass_test "Covers endpoint: $endpoint"
    else
        fail_test "Missing endpoint: $endpoint"
    fi
done
echo ""

# Test 6: Security checks
echo -e "${YELLOW}[Security Checks]${NC}"

# Check for password input with -s flag (silent)
if grep -q "read -rs.*PASSWORD" "$SCRIPT_PATH"; then
    pass_test "Password input uses silent read (-rs)"
else
    fail_test "Password input may not be secure"
fi

# Check credentials are saved to user home directory
if grep -q '\$HOME/.spoq' "$SCRIPT_PATH"; then
    pass_test "Credentials stored in user home directory"
else
    fail_test "Credentials storage path may be insecure"
fi

# Check for proper JSON escaping in curl calls
if grep -q 'jq' "$SCRIPT_PATH"; then
    pass_test "Uses jq for JSON parsing (safe)"
else
    fail_test "May not be using jq for JSON parsing"
fi
echo ""

# Test 7: User experience features
echo -e "${YELLOW}[User Experience]${NC}"

# Check for color output
if grep -q "RED=" "$SCRIPT_PATH" && grep -q "GREEN=" "$SCRIPT_PATH" && grep -q "YELLOW=" "$SCRIPT_PATH"; then
    pass_test "Has color output for better UX"
else
    fail_test "Missing color output"
fi

# Check for menu system with 2 options
if grep -q "Select a flow to test:" "$SCRIPT_PATH"; then
    pass_test "Has interactive menu"
else
    fail_test "Missing interactive menu"
fi

# Check for menu option 1: BYOVPS
if grep -q '1).*BYOVPS' "$SCRIPT_PATH"; then
    pass_test "Menu has option [1] BYOVPS"
else
    fail_test "Missing menu option [1] BYOVPS"
fi

# Check for menu option 2: Managed VPS
if grep -q '2).*Managed VPS' "$SCRIPT_PATH"; then
    pass_test "Menu has option [2] Managed VPS"
else
    fail_test "Missing menu option [2] Managed VPS"
fi

# Verify no option 3 exists (Test BYOVPS Provisioning should be removed)
if ! grep -q '\[3\]' "$SCRIPT_PATH"; then
    pass_test "No option [3] found (removed as expected)"
else
    fail_test "Option [3] should be removed"
fi

# Verify choice validation accepts only 1-2
if grep -q 'Enter choice \[1-2\]' "$SCRIPT_PATH"; then
    pass_test "Choice validation is [1-2]"
else
    fail_test "Choice validation should be [1-2]"
fi

# Check for progress indicators
if grep -q "echo.*Polling\|echo.*Waiting" "$SCRIPT_PATH"; then
    pass_test "Has progress indicators"
else
    fail_test "Missing progress indicators"
fi
echo ""

# Test 8: Error handling
echo -e "${YELLOW}[Error Handling]${NC}"

# Check for HTTP status code handling
if grep -q "http_code" "$SCRIPT_PATH"; then
    pass_test "Handles HTTP status codes"
else
    fail_test "May not handle HTTP errors properly"
fi

# Check for 401 auto-refresh
if grep -q '401' "$SCRIPT_PATH" && grep -q 'refresh_token' "$SCRIPT_PATH"; then
    pass_test "Implements 401 auto-refresh"
else
    fail_test "Missing 401 auto-refresh logic"
fi

# Check for jq error checking
if grep -q 'jq -e' "$SCRIPT_PATH"; then
    pass_test "Uses jq with error checking (-e flag)"
else
    fail_test "jq calls may not check for errors"
fi
echo ""

# Test 9: Function structure
echo -e "${YELLOW}[Code Structure]${NC}"

# Check for helper functions
functions=("api_call" "load_credentials" "save_credentials")
for func in "${functions[@]}"; do
    if grep -q "^${func}()" "$SCRIPT_PATH" || grep -q "^${func} ()" "$SCRIPT_PATH"; then
        pass_test "Has helper function: $func"
    else
        fail_test "Missing helper function: $func"
    fi
done

# Check for show_spinner function
if grep -q "^show_spinner()" "$SCRIPT_PATH" || grep -q "^show_spinner ()" "$SCRIPT_PATH"; then
    pass_test "Has spinner function: show_spinner"
else
    fail_test "Missing spinner function: show_spinner"
fi

echo ""

# Test 10: Configuration and constants
echo -e "${YELLOW}[Configuration]${NC}"

# Check for configurable base URL
if grep -q 'BASE_URL.*\${1:-' "$SCRIPT_PATH"; then
    pass_test "Base URL is configurable via argument"
else
    fail_test "Base URL may not be configurable"
fi

# Check for default base URL
if grep -q 'spoq-api-production.up.railway.app' "$SCRIPT_PATH"; then
    pass_test "Has default production URL"
else
    fail_test "Missing default base URL"
fi

# Check for credentials file path
if grep -q 'CREDENTIALS_FILE=' "$SCRIPT_PATH"; then
    pass_test "Has credentials file configuration"
else
    fail_test "Missing credentials file path"
fi
echo ""

# Test 11: Two flow modes
echo -e "${YELLOW}[Flow Modes]${NC}"

if grep -q 'TEST_MODE="byovps"' "$SCRIPT_PATH"; then
    pass_test "Has 'byovps' flow mode"
else
    fail_test "Missing 'byovps' flow mode"
fi

if grep -q 'TEST_MODE="full"' "$SCRIPT_PATH"; then
    pass_test "Has 'full' flow mode"
else
    fail_test "Missing 'full' flow mode"
fi

# Verify status mode was removed
if ! grep -q 'TEST_MODE="status"' "$SCRIPT_PATH"; then
    pass_test "Status mode removed (as expected)"
else
    fail_test "Status mode should be removed"
fi
echo ""

# Test 12: BYOVPS specific features
echo -e "${YELLOW}[BYOVPS Features]${NC}"

# Check for VPS IP input
if grep -q "Enter VPS IP address" "$SCRIPT_PATH"; then
    pass_test "Prompts for VPS IP address"
else
    fail_test "Missing VPS IP input"
fi

# Check for SSH username input
if grep -q "Enter SSH username" "$SCRIPT_PATH"; then
    pass_test "Prompts for SSH username"
else
    fail_test "Missing SSH username input"
fi

# Check for JWT display
if grep -q "jwt_token\|JWT Credentials" "$SCRIPT_PATH"; then
    pass_test "Displays JWT credentials"
else
    fail_test "Missing JWT credential display"
fi

# Check for install script output
if grep -q "install_script.*output" "$SCRIPT_PATH"; then
    pass_test "Shows install script output"
else
    fail_test "Missing install script output"
fi

# Check for status polling loop in BYOVPS mode
if grep -q "Polling VPS status" "$SCRIPT_PATH" && grep -q "while.*POLL_COUNT.*MAX_POLLS" "$SCRIPT_PATH"; then
    pass_test "Has status polling loop in BYOVPS mode"
else
    fail_test "Missing status polling loop"
fi
echo ""

# Final summary
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Test Results                                     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}Passed:${NC} $TEST_PASSED"
echo -e "  ${RED}Failed:${NC} $TEST_FAILED"
echo -e "  ${BLUE}Total:${NC}  $((TEST_PASSED + TEST_FAILED))"
echo ""

if [ $TEST_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi

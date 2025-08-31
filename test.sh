#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HOST="${HOST:-localhost:8787}"
ENDPOINT="${ENDPOINT:-}"
SAMPLE_FILE="sample.xml"

# Print header
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}JNLP Token Injection Worker Test Suite${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Function to run a test
run_test() {
    local test_name="$1"
    local cookies="$2"
    local expected_behavior="$3"
    local extra_headers="$4"
    
    echo -e "${YELLOW}Test: ${test_name}${NC}"
    echo -e "Cookies: ${cookies}"
    echo -e "Expected: ${expected_behavior}"
    echo ""
    
    # Build curl command
    local curl_cmd="curl -s"
    
    if [ ! -z "$cookies" ]; then
        curl_cmd="$curl_cmd --cookie \"$cookies\""
    fi
    
    curl_cmd="$curl_cmd -H \"Content-Type: application/xml\""
    curl_cmd="$curl_cmd -H \"Host: reflector.cloudflareapp.cc\""
    
    if [ ! -z "$extra_headers" ]; then
        curl_cmd="$curl_cmd $extra_headers"
    fi
    
    curl_cmd="$curl_cmd -X POST -d @${SAMPLE_FILE} ${HOST}${ENDPOINT}"
    
    echo "Command: $curl_cmd"
    echo "Response:"
    
    # Execute and capture response
    response=$(eval $curl_cmd)
    
    # Check if response contains modified http_ticket
    if echo "$response" | grep -q "http_ticket.*++.*++"; then
        echo -e "${GREEN}✓ Token injection successful${NC}"
        # Show a sample of the modified ticket
        echo "$response" | grep -o 'http_ticket" value="[^"]*' | head -1
    elif echo "$response" | grep -q "http_ticket"; then
        echo -e "${YELLOW}⚠ Response contains http_ticket but not modified${NC}"
    else
        echo -e "${RED}✗ No http_ticket found or error occurred${NC}"
        echo "$response" | head -50
    fi
    
    echo ""
    echo "----------------------------------------"
    echo ""
}

# Function to test with debug mode
run_debug_test() {
    echo -e "${BLUE}Running test with DEBUG mode enabled${NC}"
    echo ""
    
    # Note: This assumes DEBUG is set as an environment variable in wrangler.toml
    # or can be passed through the worker configuration
    curl -s \
        --cookie "CF_Authorization=test-auth-token-123" \
        -H "Content-Type: application/xml" \
        -H "Host: reflector.cloudflareapp.cc" \
        -H "CF-Connecting-IP: 192.168.1.100" \
        -X POST \
        -d @${SAMPLE_FILE} \
        ${HOST}${ENDPOINT} \
        -w "\n\nHTTP Status: %{http_code}\nTime Total: %{time_total}s\n"
}

# Test 1: Valid CF_Authorization cookie
run_test \
    "Valid CF_Authorization" \
    "cookie0=hihi;CF_Authorization=valid-auth-token-abc123;cookie1=abcdabcd;cookie2=haha" \
    "Should inject token successfully"

# Test 2: CF_Authorization with special characters (URL encoded)
run_test \
    "CF_Authorization with special characters" \
    "CF_Authorization=token%2Bwith%2Fspecial%3Dchars%0A;other_cookie=value" \
    "Should handle URL-encoded tokens"

# Test 3: Missing CF_Authorization cookie
run_test \
    "Missing CF_Authorization" \
    "cookie0=value0;cookie1=value1" \
    "Should return error or original content"

# Test 4: Empty CF_Authorization
run_test \
    "Empty CF_Authorization" \
    "CF_Authorization=;other_cookie=value" \
    "Should handle empty authorization"

# Test 5: Multiple cookies with CF_Authorization in middle
run_test \
    "CF_Authorization in middle of cookie string" \
    "session=xyz123;CF_Authorization=middle-token-456;user_pref=dark_mode;tracking_id=789" \
    "Should extract CF_Authorization correctly"

# Test 6: With custom IP header
run_test \
    "Custom IP via CF-Connecting-IP header" \
    "CF_Authorization=ip-test-token" \
    "Should use provided IP for HMAC generation" \
    "-H \"CF-Connecting-IP: 203.0.113.42\""

# Test 7: With X-Forwarded-For header
run_test \
    "Custom IP via X-Forwarded-For header" \
    "CF_Authorization=xff-test-token" \
    "Should use first IP from X-Forwarded-For" \
    "-H \"X-Forwarded-For: 198.51.100.178, 203.0.113.42\""

# Optional: Run debug test if requested
if [ "$1" == "--debug" ] || [ "$1" == "-d" ]; then
    echo ""
    run_debug_test
fi

# Summary
echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Test Suite Complete${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo "Usage:"
echo "  ./test.sh           - Run all tests"
echo "  ./test.sh --debug   - Run tests with debug output"
echo ""
echo "Environment variables:"
echo "  HOST=<host:port>    - Override test host (default: localhost:8787)"
echo "  ENDPOINT=<path>     - Add endpoint path if needed"
#!/bin/bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

HURL_DIR="hurl"
VERBOSE=false

if [[ "$1" == "--verbose" ]] || [[ "$1" == "-v" ]]; then
    VERBOSE=true
fi

export admin_email="${ADMIN_EMAIL:-admin@example.com}"
export admin_password="${ADMIN_PASSWORD:-Admin123}"
export group_user_username="${GROUP_USER_USERNAME:-testuser}"
export group_user_password="${GROUP_USER_PASSWORD:-Test123}"

echo -e "${YELLOW}🧪 Running Hurl tests...${NC}"
echo ""

if ! curl -s http://localhost:3000/api/health > /dev/null 2>&1; then
    echo -e "${RED}❌ Server is not running on http://localhost:3000${NC}"
    echo -e "${YELLOW}💡 Start the server first:${NC}"
    echo "   cargo run"
    exit 1
fi

echo -e "${GREEN}✓ Server is running${NC}"
echo ""

total_files=0
passed_files=0
failed_files=0

for hurl_file in "$HURL_DIR"/*.hurl; do
    if [ ! -f "$hurl_file" ]; then
        continue
    fi

    total_files=$((total_files + 1))
    filename=$(basename "$hurl_file")

    echo -e "${YELLOW}▶ Running $filename${NC}"

    if [ "$VERBOSE" = true ]; then
        if hurl --test --very-verbose "$hurl_file"; then
            echo -e "${GREEN}✓ $filename passed${NC}"
            passed_files=$((passed_files + 1))
        else
            echo -e "${RED}✗ $filename failed${NC}"
            failed_files=$((failed_files + 1))
        fi
    else
        if hurl --test "$hurl_file" 2>&1 | grep -v "^$"; then
            echo -e "${GREEN}✓ $filename passed${NC}"
            passed_files=$((passed_files + 1))
        else
            echo -e "${RED}✗ $filename failed${NC}"
            failed_files=$((failed_files + 1))
        fi
    fi

    echo ""
done

# Resumo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${YELLOW}📊 Test Summary:${NC}"
echo "   Total files:  $total_files"
echo -e "   ${GREEN}Passed:       $passed_files${NC}"
echo -e "   ${RED}Failed:       $failed_files${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $failed_files -eq 0 ]; then
    echo -e "${GREEN}✨ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}💥 Some tests failed${NC}"
    exit 1
fi

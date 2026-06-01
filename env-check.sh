#!/bin/bash

###############################################################################
# Environment Readiness Check Script
#
# Purpose:
#   Performs pre-demo validation checks commonly required before running
#   customer PoCs, workshops, or technical demonstrations.
#
# Designed For:
#   Docker-based demo environments, Kubernetes PoCs, and lab deployments.
#
# Checks Performed:
#   1. Docker daemon availability
#   2. Kubernetes cluster connectivity via kubectl
#   3. Port 80 listening status
#   4. curl installation availability
#
# If a check fails:
#   Investigate the corresponding service, correct the issue,
#   and rerun the script before proceeding with the demo.
###############################################################################

set -euo pipefail

# Print a useful error message if the script exits unexpectedly
trap 'echo "ERROR: Script failed unexpectedly at line $LINENO"; exit 1' ERR

PASSED=0
TOTAL=4

echo "Starting environment validation..."
echo

###############################################################################
# Docker Check
###############################################################################
if docker info >/dev/null 2>&1; then
    echo "✔ Docker is running"
    ((PASSED++))
else
    echo "✗ Docker is not running"
fi

###############################################################################
# Kubernetes Connectivity Check
###############################################################################
if kubectl cluster-info >/dev/null 2>&1; then
    echo "✔ Kubernetes cluster is reachable"
    ((PASSED++))
else
    echo "✗ Kubernetes cluster is unreachable"
fi

###############################################################################
# Port 80 Check
###############################################################################
if ss -tuln 2>/dev/null | grep -q ":80 "; then
    echo "✔ Port 80 is open"
    ((PASSED++))
else
    echo "✗ Port 80 is not open"
fi

###############################################################################
# curl Availability Check
###############################################################################
if command -v curl >/dev/null 2>&1; then
    echo "✔ curl is available"
    ((PASSED++))
else
    echo "✗ curl is not available"
fi

echo
echo "Environment check complete. ${PASSED}/${TOTAL} checks passed."

# Exit code handling
if [ "$PASSED" -eq "$TOTAL" ]; then
    exit 0
else
    exit 1
fi

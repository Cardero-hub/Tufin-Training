#!/bin/bash

###############################################################################
# Harrington & Voss PoC Environment Validation Script
#
# Purpose:
#   Performs readiness checks for the Harrington & Voss Proof of Concept
#   environment before onboarding devices and validating integrations.
#
# Checks Performed:
#   1. Docker daemon availability (local container runtime)
#   2. Kubernetes cluster connectivity (local orchestration platform)
#   3. AWS EC2 reachability via HTTP (cloud-hosted PoC server)
#
# If a check fails:
#   Investigate the corresponding component and rerun the script before
#   continuing with the PoC activities.
###############################################################################

set -euo pipefail

# Print a useful error message if the script exits unexpectedly
trap 'echo "ERROR: Script failed unexpectedly at line $LINENO"; exit 1' ERR

PASSED=0
TOTAL=3

# Replace with your actual EC2 public IP
EC2_IP="YOUR_PUBLIC_IP"

echo "Starting Harrington & Voss PoC environment validation..."
echo

###############################################################################
# Docker Check
###############################################################################
if docker info >/dev/null 2>&1; then
    echo "✔ Docker is running"
    ((PASSED++))
else
    echo "✗[FAIL] Docker validation failed.
No running Docker containers detected.

Action:
Start Docker Desktop and verify required containers are running.

Exiting with code 1."
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
# AWS EC2 Reachability Check
###############################################################################
EC2_IP=16.170.85.238

if curl -s --connect-timeout 5 "http://${EC2_IP}" >/dev/null 2>&1; then
    echo "✔ AWS EC2 instance is reachable"
    ((PASSED++))
else
    echo "✗ AWS EC2 instance is unreachable"
fi

echo
echo "PoC Environment Status: ${PASSED}/${TOTAL} components ready"

# Exit code handling
if [ "$PASSED" -eq "$TOTAL" ]; then
    exit 0
else
    exit 1
fi

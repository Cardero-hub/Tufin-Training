# Harrington & Voss PoC Installation Log

Date: 2026-06-02

## Initial Capstone Environment Setup

Docker
- Required to run containerized services and applications(simulated Tufin SecureTrack+ application components)

Kubernetes
- Required to orchestrate and manage the containerized Tufin services

Helm
- Required to deploy and manage the Kubernetes resources for the Tufin application consistently and repeatably

AWS EC2
- Required to provide cloud-hosted infrastructure for demonstrating Harrington & Voss's data center deployment and connectivity scenarios.

PoC Workspace
- Required to organize all configuration files, validation scripts, logs, and deliverables for the Harrington & Voss engagement.




## Kubernetes Deployment Validation

Component: Kubernetes Test Deployment

Status: SUCCESS

Validation:
- Confirmed two pods running the poc-test applications successfuly deployed and service is accessible through the browser.




## AWS EC2 Setup

Component name : harrington-poc-server

Public IP: 16.170.85.238

Status: SUCCESS/RUNNING

Validation:
- EC2 instance represents the cloud-side infrastructure (Data Center where Harrington's Checkpoint SG) that Tufin would need to communicate with and manage as part of a hybrid enterprise environment.

- Opening ports to 0.0.0.0/0 exposes the PoC to the entire internet, creating a direct attack surface and violating enterprise security standards. Even temporary exposure risks scanning, exploitation, and data leakage during client demonstrations.≈




## Environment Hardening     

 Date: 2026-06-03

- EC2 status: OK
- Docker: running
- Kubernetes: healthy
- Security groups: correctly restricted
- Public IP verified




## Full Environment Baseline Check

Date: 2026-06-34 10:20

Day 9 baseline check completed.

-Validation script returned exit code 0.
-Kubernetes deployment healthy with both poc-test pods running.
-EC2 instance reachable via SSH, Docker operational, disk usage normal.

All components confirmed green before fault testing.




## Fault Test — Kubernetes Self-Heal Under Load 

Deleted pod:
poc-test-586f95b5d4-vgbxj

Recovery time:
2.75 seconds

What we're seeing here is Kubernetes detecting that one of the application instances has unexpectedly disappeared. The deployment is configured to maintain three healthy replicas, so the control plane automatically creates a replacement pod to restore the desired state. This self-healing behaviour reduces operational risk because service availability is maintained without requiring manual intervention from the operations team.




## Fault Test — AWS Security Group Block

- Diagnostic steps
1. Check to confirm the EC2 instance is running.
2. Verify the public IP address being used is correct.
3. Review the security group attached to the instance.
4. Check whether an inbound rule exists for TCP port 8443.
5. Verify the source restriction allows my current public IP.
6. Restore the missing rule and retest connectivity.


- Removing the inbound 8443 rule caused AWS to drop traffic before it reached the EC2 instance; the same issue commonly occurs during client PoCs when security teams modify firewall or security group policies between validation and demonstration sessions.



## Fault Test — Validation Script Failure Detection

- If the validation script had failed silently, the demo could have started with critical services unavailable while incorrectly appearing healthy; explicit exit codes provide an immediate and reliable signal that remediation is required before proceeding.

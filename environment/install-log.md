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

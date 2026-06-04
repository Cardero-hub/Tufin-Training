# Harrington & Voss Pre-Demo Checklist



## Local Environment

1. [ ] Docker running

  * Expected: Docker Desktop operational and containers healthy
  * If failed: Start Docker and verify container status

2. [ ] Kubernetes cluster healthy

  * Expected: kubectl get nodes returns Ready
  * If failed: Restart cluster and verify connectivity

3. [ ] Validation script passes

  * Expected: Exit code 0
  * If failed: Review failed check and remediate before continuing

4. [ ] Directory structure present

  * Expected: All Harrington PoC folders accessible
  * If failed: Restore missing files from GitHub



## AWS Environment

1. [ ] EC2 instance running

  * Expected: Running state in AWS Console
  * If failed: Start instance and wait for health checks

2. [ ] SSH access confirmed

  * Expected: Successful SSH login
  * If failed: Verify security group and source IP

3. [ ] Docker running on EC2

  * Expected: docker ps returns active containers
  * If failed: Restart Docker service

4. [ ] Security group validated

  * Expected: Ports 22, 80 and 8443 allowed from my IP only
  * If failed: Correct inbound rules



## Application Layer

1. [ ] poc-test deployment healthy

  * Expected: Desired pods in Running state
  * If failed: Review deployment events and recreate pods

2. [ ] NodePort service reachable

  * Expected: Application loads successfully in browser
  * If failed: Verify service, pod status and networking



## Files

1. [ ] onboarding-report.txt present

  * Expected: Readable and complete
  * If failed: Restore from repository

2. [ ] api-log.md complete

  * Expected: Validation evidence documented
  * If failed: Update before demo

3. [ ] install-log.md current

  * Expected: Latest troubleshooting recorded
  * If failed: Update immediately



## Loom Recording Plan


1. [ ] Recording sequence reviewed

  * Expected: Intro → Environment → Onboarding → API → Fault Testing → Summary
  


## Communication

1. [ ] Client-facing contingency message prepared

  * Expected: Ready to send if technical issue occurs
  


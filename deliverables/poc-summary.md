# PoC Summary: Harrington & Voss Financial Services


### Background Information

This PoC evaluated whether Tufin SecureTrack+ can provide unified firewall visibility, cross-vendor policy correlation, compliance reporting, and workflow automation across Harrington & Voss’s Fortinet and Check Point environments. The environment was built to reflect a hybrid enterprise model, with a Local Linux machine representing distributed office FortiGate firewall estates and an AWS EC2 Instance representing remote Check Point data centre setup, all normalised through a simulated SecureTrack deployment.

The validation focused on three areas: ingestion of multi-vendor firewall configurations, REST API-driven policy visibility, and generation of a unified operational and compliance view. The onboarding process confirmed that both Fortinet and Check Point configurations can be normalised into a single policy model, enabling consistent interpretation of rules across otherwise isolated security teams. The API layer demonstrated that device and rule data can be retrieved consistently, but also highlighted the dependency on a correct onboarding structure for meaningful aggregation.



### Objective 1: Unified view of firewall rules

The PoC confirmed that Tufin can consolidate Fortinet and Check Point firewall rules into a single operational view. The onboarding scripts successfully mapped vendor-specific configurations into a shared rule structure, allowing policies to be viewed consistently across both office and data centre environments, as seen in the auto-generated report. This directly addresses the current visibility gap between the Frankfurt network operations team and the London data centre security team.



### Objective 2: Cross-vendor policy conflict detection

The analysis identified that policy conflicts arise not within individual vendor environments, but between overlapping rule intent across domains. The simulated comparison logic demonstrated that Tufin can surface these inconsistencies when rules are normalised into a common model. For instance, it detected an active path between the Dataceter and Office locations that neither team has visibility into. This capability reduces the risk of undetected cross-environment interactions that previously led to service disruptions lasting several hours.



### Objective 3: PCI DSS compliance reporting

The PoC demonstrated that compliance reporting can be generated across both environments in a single consolidated output (on-boarding report file). Compared to the current manual process, which takes approximately four weeks, the automated approach reduces reporting time to near real-time generation once data is onboarded. The key dependency is consistent rule classification during ingestion, which directly impacts report accuracy.



### Objective 4: ServiceNow integration workflow

The PoC confirmed that change requests can be mapped into a structured workflow where ServiceNow acts as the intake layer, and Tufin governs policy validation and enforcement logic. While full production integration was not deployed, the simulated workflow showed how changes can be assessed against existing policies before implementation, reducing the risk of manual misconfiguration across vendor boundaries.



### Cross-Vendor Visibility Gap (Business Risk)



The current architecture forces Fortinet and Check Point teams to operate in isolation, meaning there is no unified understanding of how policy changes in one environment affect the other. The PoC highlighted that this creates a blind spot where cross-domain rule interactions can silently introduce service disruption. The business impact is increased incident resolution time, inconsistent compliance reporting, and elevated operational risk during policy changes across teams.

### Recommended Next Steps

Proceed to a production-aligned pilot using live Fortinet and Check Point integrations with SecureTrack enabled for continuous policy ingestion. Expand onboarding coverage to include full rule metadata classification to improve compliance reporting accuracy. Introduce ServiceNow integration into a controlled change workflow for validation against real ticket data. This phase should be executed within a 30-day window to align with Q4 security governance reporting requirements.

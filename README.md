# FortiGate IPS Custom Anomaly for Alcatel-Lucent Enterprise Network Advisor

This custom anomaly for OmniVista Network Advisor has been created to integrate with the Intrusion Prevention System (IPS) of Fortinet FortiGate devices.

## Description
When the FortiGate IPS detects an attack, a notification is sent that includes a suggested remediation action (blocking the attacker). This action generates a syslog message or a REST call to OmniVista. OmniVista then leverages its Quarantine Manager feature to isolate the attacker on managed OmniSwitches or the Blocklist feature to isolate the attacker on managed Stellar Access Points.
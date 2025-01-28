THE SOFTWARE IS PROVIDED “AS IS,” WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE WARRANTIES OR MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT, AND WITHOUT ANY SUPPORT, UPDATES, OR MAINTENANCE. IN NO EVENT SHALL ALCATEL-LUCENT ENTERPRISE BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OR OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# FortiGate IPS Custom Anomaly for Alcatel-Lucent Enterprise Network Advisor

This custom anomaly for OmniVista Network Advisor has been created to integrate with the Intrusion Prevention System (IPS) of Fortinet FortiGate devices.

## Description
When the FortiGate IPS detects an attack, a notification is sent that includes a suggested remediation action (blocking the attacker). This action generates a syslog message or a REST call to OmniVista. OmniVista then leverages its Quarantine Manager feature to isolate the attacker on managed OmniSwitches or the Blocklist feature to isolate the attacker on managed Stellar Access Points.

## Requirements
- **OmniVista Network Advisor** version **1.4** or higher is required for this custom anomaly to work correctly.
- **OmniVista 2500**.

## Installation
1. Download the archive from the following link: [Fortigate_IPS.zip](https://github.com/ale-nsa-team/omnivista-network-advisor-fortigate-ips/releases/download/v1.0.0/Fortigate_IPS.zip)
2. Open **OmniVista Network Advisor** and navigate to the **Anomaly Monitoring** section.
3. Click on the green **Import Custom Anomaly** button.
4. Select the downloaded archive (`Fortigate_IPS.zip`) and import it into OmniVista Network Advisor.
5. SSH into the **OmniVista Network Advisor** host and modify the file located at:  
   `/opt/Alcatel-Lucent_Enterprise/NetworkAdvisor/ovna-rsyslog/watchdogs-custom/Fortigate_IPS/omnivista/omnivista.json`
   Update the following fields in the file with your **OmniVista 2500** credentials:
   - IP address
   - Login
   - Password

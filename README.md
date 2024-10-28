THE SOFTWARE IS PROVIDED “AS IS,” WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE WARRANTIES OR MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT, AND WITHOUT ANY SUPPORT, UPDATES, OR MAINTENANCE. IN NO EVENT SHALL ALCATEL-LUCENT ENTERPRISE BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OR OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# FortiGate IPS Custom Anomaly for Alcatel-Lucent Enterprise Network Advisor

This custom anomaly for OmniVista Network Advisor has been created to integrate with the Intrusion Prevention System (IPS) of Fortinet FortiGate devices.

## Description
When the FortiGate IPS detects an attack, a notification is sent that includes a suggested remediation action (blocking the attacker). This action generates a syslog message or a REST call to OmniVista. OmniVista then leverages its Quarantine Manager feature to isolate the attacker on managed OmniSwitches or the Blocklist feature to isolate the attacker on managed Stellar Access Points.

Edward (Duke) Alf
Tufts COMP 116 - Intro to Security
lab4 - Incident Alarm

In this assignment, I use Python and the Scapy library to build a network sniffing tool that can detect security incidents
by analyzing a stream of network packets. This alarm can detect specific scans and even acquire usernames and passwords
sent unencrypted. The goal of the assignment was to understand how tools such as Ettercap and Wireshark work under the
hood.

Correctly Implemented:
-detect NULL scan
-detect FIN scan
-detect Xmas scan
-detect usernames and passwords sent via HTTP, FTP, IMAP
-detect Nikto scan
-detect RDP scan

Collaborations:
None other than Piazza, Scapy documentation, and some basic Googling.

Time spent:
~8 hours

Are the heuristics used in this assignment to determine incidents "even that good"?
No, there are methods to scan that would fail to be detected by this program. For example, one could use a Stealthy
scan. In addition, the code to detect these scans look for specific keywords in the payload, so packets could
get by with valuable information such as usernames and passwords.

If you have spare time in the future, what would you add to the program or do differently with regards to detecting
incidents?
One optimization would be to detect if the credentials are actually valid, and not just failed login attempts. This
would involve finding more information about the response to a login attempt. Furthermore, a way to detect which
scans are harmful would be interesting, rather than getting a ton of alerts about casual scans.
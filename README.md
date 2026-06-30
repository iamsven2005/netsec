Hi all, I roughly broke down the ICT2217 project timeline so we don’t rush at the end. We have about **23 May – 7 Jul**.

**Week 1 (23–29 May)**

* Finalise topology + IP plan
* Send rack request
* Confirm devices and roles
* Prepare report skeleton

**Week 2 (30 May – 5 Jun)**

* Setup network infra
* Router + firewall + VLANs + DMZ
* Get connectivity working

**Week 3 (6–12 Jun)**

* Setup RPi OpenPLC + Modbus
* Bring HMI online
* Test FC01 / FC03 / FC05 / FC15
* Capture normal traffic

**Week 4 (13–19 Jun)**

* Develop Scapy attack tool
* Packet sniffing + FC15 injection
* Test PLC manipulation
* Optional MITM

**Week 5 (20–26 Jun)**

* Implement defenses
* ACL
* Firewall rules
* Port security
* VLAN isolation
* Retest attacks

**Week 6 (27 Jun – 3 Jul)**

* Report writing
* Screenshots
* Wireshark captures
* Topology diagrams

**Final week (4–7 Jul)**

* Full demo rehearsal
* Fix issues
* Final report + submission

Suggested target: **attack working by 19 Jun**, otherwise July may become very tight 😅

Report document:
https://docs.google.com/document/d/1XUnHJ_M1wCz90MIbPeqOzpmUXQBvzkyq/edit?usp=sharing&ouid=111394012869341403431&rtpof=true&sd=true


plug wire to mgt port and a management cable to fw2 on the patch panel

on your laptop, change address to 192.168.1.2 (or wtv samw subnet address

visit https://192.168.1.1
username admin
password admin
change password to Student@s1t

go to tera term and type admin and Student@s1t

set system ztp disable

wait for the https page to come back online

login again

at the grey top panel, look for device

look for operation at the top bar of the device page

click on import config and import the XML file

once done click on load config in same page

at the top left corner of the page you should see a commit button

click and wait for changes

test if it works
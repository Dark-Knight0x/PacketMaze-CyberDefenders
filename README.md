# PacketMaze — CyberDefenders Lab Writeup
[BlueTeam CTF Challenges – PacketMaze](https://cyberdefenders.org/blueteam-ctf-challenges/packetmaze/)
## Overview

**Category:** `Network Forensics`  
**Tactic:** Initial Access  
**Tools:** `Wireshark`,  `MAC Lookup`  
**Difficulty:** Medium  
**Completion:** 11/11 Questions (100%)

This lab involves analyzing a network packet capture (PCAP) to identify suspicious activity, extract Indicators of Compromise (IOCs), and uncover authentication details, file transfers, and server information across multiple protocols.

> 🔒 The challenge file is unzipped with the password: `cyberdefenders.org`

---

## Questions & Findings

---

### Q1 — What is the FTP password?

**Tool:** Wireshark  
**Filter:** `ftp`

Open the PCAP in Wireshark and filter for FTP traffic. FTP transmits credentials in plaintext. Look for the `PASS` command in the FTP stream to reveal the password.

<img width="2011" height="430" alt="image" src="https://github.com/user-attachments/assets/6c56b44a-3033-4127-b5fb-1ba3e7040e26" />





**Answer:** `AfricaCTF2021`

---

### Q2 — What is the IPv6 address of the DNS server used by 192.168.1.26?

**Tool:** Wireshark  
**Filter:** `ipv6 && dns`

Using the filter `ipv6 && dns` in Wireshark, we only display DNS packets over IPv6.
By observing the Destination column, the address fe80::c80b:adff:feaa:1db7 appears as the receiver of DNS queries, so this is the IPv6 address of the DNS server used by 192.168.1.26. 

<img width="2555" height="393" alt="image" src="https://github.com/user-attachments/assets/a966b662-6bc9-4b4a-b5b1-c32b62c7de3e" />



**Answer:** `fe80::c80b:adff:feaa:1db7`

---

### Q3 — What domain is the user looking up in packet 15174?

**Tool:** Wireshark  
**Filter:** `frame.number == 15174`

Navigate directly to frame 15174. Expand the DNS query section in the packet details to view the domain name being resolved.

<img width="1275" height="233" alt="image" src="https://github.com/user-attachments/assets/73d3d904-eb75-47cb-a058-b92988e25609" />



**Answer:** `www.7-zip.org`

---

### Q4 — How many UDP packets were sent from 192.168.1.26 to 24.39.217.246?

**Tool:** Wireshark  
**Filter:** `ip.src == 192.168.1.26 && ip.dst == 24.39.217.246 && udp`

Apply the filter and check the status bar at the bottom of Wireshark for the total packet count.

<img width="1275" height="1244" alt="image" src="https://github.com/user-attachments/assets/2146a168-0039-4980-923a-b8320c4a0d9d" />



**Answer:** `10`

---

### Q5 — What is the MAC address of the system under investigation?

**Tool:** Wireshark / NetworkMiner

Filter traffic originating from `192.168.1.26`. Inspect the Ethernet layer of any packet to retrieve the source MAC address of the host.

<img width="1281" height="1181" alt="image" src="https://github.com/user-attachments/assets/d368bbff-4406-49f8-b8ef-0a85fbcce9ba" />



**Answer:** `c8:09:a8:57:47:93`

---

### Q6 — What was the camera model used to take picture `20210429_152157.jpg`?

**Tool:** NetworkMiner / Wireshark file export

By applying the filter `_ws.col.info == "FTP Data: 1460 bytes (PASV) (STOR 20210429_152157.jpg)"` in Wireshark, we can follow the entire TCP session related to the FTP file transfer between 192.168.1.26 and 192.168.1.20. In the FTP-Data section, the command `STOR 20210429_152157.jpg` confirms that the image file was uploaded via FTP. After selecting `Follow` → `TCP Stream`, the full content of the transferred JPG file is displayed. In the raw data, the EXIF metadata reveals the manufacturer “LG Electronics” and the camera model `“LM-Q725K”`. Therefore, the camera model used to take the picture `20210429_152157.jpg` is `LM-Q725K`.

<img width="2559" height="1248" alt="image" src="https://github.com/user-attachments/assets/325b157c-8cfd-4cf3-87e6-db9a579ec754" />


<img width="1659" height="604" alt="image" src="https://github.com/user-attachments/assets/15b98afb-b081-469e-9836-218ea4f557ec" />


**Answer:** `LM-Q725K`

---

### Q7 — What is the ephemeral public key in the TLS handshake for session ID `da4a0000342e4b73...`?

**Tool:** Wireshark  
**Filter:** `tls`

<img width="2554" height="694" alt="image" src="https://github.com/user-attachments/assets/13a39b57-5fc6-49de-9704-677b55fb66d3" />


<img width="1431" height="534" alt="image" src="https://github.com/user-attachments/assets/13ea75a7-daef-4fa5-a26a-9f59bd2fb82a" />



Filter for TLS traffic and locate the `Server Hello` packet matching the specified session ID. Expand the TLS layer → Handshake Protocol → Server Key Exchange to find the ephemeral public key value.

**Answer:** *04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d*

---

### Q8 — What is the first TLS 1.3 client random used to connect to protonmail.com?

**Tool:** Wireshark  
**Filter:** `_ws.col.protocol == "TLSv1.3"` (Client Hello)

<img width="2559" height="856" alt="image" src="https://github.com/user-attachments/assets/ae6ca2f4-60d3-48c1-99e2-f1992424dd30" />



Filter for TLS Client Hello packets and look for the SNI (Server Name Indication) field containing `protonmail.com`. Expand TLS → Handshake Protocol → Client Hello → Random to extract the 32-byte client random value.

**Answer:** *24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70*

---

### Q9 — Which country is the manufacturer of the FTP server's MAC address registered in?

**Tool:** Wireshark + MAC Address Lookup (e.g., maclookup.app)

<img width="1156" height="676" alt="image" src="https://github.com/user-attachments/assets/19939a7c-4893-4bc8-bcf1-0379ef1470cd" />



Identify the FTP server's IP from the FTP stream, then extract its MAC address from the Ethernet layer. Use an OUI/MAC lookup tool to determine the registered country of the manufacturer.

**Answer:** `United States`

---

### Q10 — What time was a non-standard folder created on the FTP server on April 20th?

**Tool:** Wireshark  
**Filter:** `ftp`

<img width="832" height="240" alt="image" src="https://github.com/user-attachments/assets/d017a37d-77cb-43a4-a3be-9283a3cb9927" />



Analyze FTP command traffic for directory listings (`LIST` responses). Look for `MKD` (Make Directory) commands or `LIST` responses on April 20th that reference non-standard folder names, and extract the associated timestamp.

**Answer:** `17:53`

---

### Q11 — What URL was visited that resolves to 104.21.89.171?

**Tool:** Wireshark  
**Filter:** `ip.addr == 104.21.89.171`

<img width="1664" height="662" alt="image" src="https://github.com/user-attachments/assets/e7211a45-8032-456c-9ab8-ff4791088e8e" />



<img width="2537" height="399" alt="image" src="https://github.com/user-attachments/assets/b02a3e53-afc0-4c1e-98b2-321965a62d44" />



Filter traffic to/from `104.21.89.171`. Inspect HTTP or TLS SNI fields within the packets to identify the hostname/URL that was visited. Cross-reference with DNS responses to confirm the domain resolves to this IP.

**Answer:** *[(Full URL)](http://dfir.science/)*

---

## Skills Demonstrated

- Network traffic analysis using Wireshark filters
- FTP credential extraction from plaintext protocols
- IPv6 DNS server identification
- TLS handshake inspection (session ID, client random, ephemeral keys)
- File extraction and EXIF metadata analysis
- MAC address OUI lookup and geolocation
- FTP directory event timeline reconstruction

---

## Conclusion

The PacketMaze lab demonstrates comprehensive network forensics analysis across multiple protocols — FTP, DNS, UDP, TLS, and HTTP. By combining Wireshark's deep packet inspection with tools like NetworkMiner and MAC lookup services, analysts can extract a wide range of forensic artifacts from a single PCAP file, including credentials, metadata, cryptographic parameters, and browsing activity.

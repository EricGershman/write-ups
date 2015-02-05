# SANS DFIR Monterey 2015 Network Forensics Challenge 
The original challange was posted to: https://www.surveymonkey.com/s/BZMXTKM

##Write-up

### Question 1 
 > *1. Difficulty: Easy
 
 > Evidence: SWT-syslog_messages
 
 > Question: At what time (UTC, including year) did the portscanning activity from IP address 123.150.207.231 start?

```bash
Aug 29 07:07:44 gw ntpd[1115]: ntpd 4.2.4p8@1.1612-o Fri Feb 22 11:23:27 UTC 2013 (1)
Aug 29 07:07:44 gw ntpd[1116]: precision = 15.532 usec
Aug 29 07:07:40 gw kernel: rtc_cmos rtc_cmos: setting system clock to 2013-08-29 11:07:08 UTC (1377774428)

Aug 29 09:58:55 gw kernel: FW reject_input: IN=eth0 OUT= MAC=08:00:27:53:38:ee:08:00:27:1c:21:2b:08:00 SRC=123.150.207.231 DST=98.252.16.36 LEN=44 TOS=0x00 PREC=0x00 TTL=41 ID=35517 PROTO=TCP SPT=38553 DPT=3306 WINDOW=1024 RES=0x00 SYN URGP=0 
Aug 29 09:58:56 gw kernel: FW reject_input: IN=eth0 OUT= MAC=08:00:27:53:38:ee:08:00:27:1c:21:2b:08:00 SRC=123.150.207.231 DST=98.252.16.36 LEN=44 TOS=0x00 PREC=0x00 TTL=34 ID=45569 PROTO=TCP SPT=38553 DPT=587 WINDOW=1024 RES=0x00 SYN URGP=0 
Aug 29 09:58:56 gw kernel: FW reject_input: IN=eth0 OUT= MAC=08:00:27:53:38:ee:08:00:27:1c:21:2b:08:00 SRC=123.150.207.231 DST=98.252.16.36 LEN=44 TOS=0x00 PREC=0x00 TTL=26 ID=46106 PROTO=TCP SPT=38553 DPT=53 WINDOW=1024 RES=0x00 SYN URGP=0 
Aug 29 09:58:57 gw kernel: FW reject_input: IN=eth0 OUT= MAC=08:00:27:53:38:ee:08:00:27:1c:21:2b:08:00 SRC=123.150.207.231 DST=98.252.16.36 LEN=44 TOS=
```

The time difference is +4 from UTC, when adding 4 hours to 09:58:55 we get 13:58:55 as the time.

Answer: **2013-08-29 13:58:55**

###Question 2 
 > *2. Difficulty: Easy
 
 > Evidence: nitroba.pcap
 
 > Question: What IP addresses were used by the system claiming the MAC Address 00:1f:f3:5a:77:9b?

```
$ tcpdump -ennnr nitroba.pcap | grep -i "00:1f:f3:5a:77:9b" | grep -vi arp
22:09:07.836909 00:1f:f3:5a:77:9b > 01:00:5e:00:00:02, ethertype IPv4 (0x0800), length 64: 192.168.1.64 > 224.0.0.2: igmp leave 224.0.0.251
22:09:07.836917 00:1f:f3:5a:77:9b > 01:00:5e:00:00:fb, ethertype IPv4 (0x0800), length 64: 192.168.1.64 > 224.0.0.251: igmp v2 report 224.0.0.25

$ tcpdump -ennnr nitroba.pcap | grep -i "00:1f:f3:5a:77:9b" | grep IPv4 | grep 00:1f:f3:5a:77:9b
22:04:06.658884 00:1f:f3:5a:77:9b > 01:00:5e:00:00:02, ethertype IPv4 (0x0800), length 64: 169.254.90.183 > 224.0.0.2: igmp leave 224.0.0.251
...
22:09:07.836909 00:1f:f3:5a:77:9b > 01:00:5e:00:00:02, ethertype IPv4 (0x0800), length 64: 192.168.1.64 > 224.0.0.2: igmp leave 224.0.0.251
...
22:20:20.478514 00:1f:f3:5a:77:9b > 01:00:5e:00:00:fb, ethertype IPv4 (0x0800), length 64: 169.254.20.167 > 224.0.0.251: igmp v2 report 224.0.0.251
```

Answer: **192.168.1.64, 169.254.90.183, 169.254.20.167**


###Question 3
 > *3. Difficulty: Medium
 
 > Evidence: ftp-example.pcap
 
 > Question: What IP (source and destination) and TCP ports (source and destination) are used to transfer the “scenery-backgrounds-6.0.0-1.el6.noarch.rpm” file?

```
$ tcpdump -A -nnnr ftp-example.pcap | less

11:39:37.716671 IP 192.168.75.29.37028 > 149.20.20.135.21: Flags [P.], seq 305:354, ack 3517, win 336, options [nop,nop,TS val 2505517924 ecr 167], len
gth 49
E..e..@.@.....K.........,._`J^.B...P.......
.W+d....RETR scenery-backgrounds-6.0.0-1.el6.noarch.rpm

11:39:37.806367 IP 149.20.20.135.21 > 192.168.75.29.37028: Flags [P.], seq 3517:3623, ack 354, win 33580, options [nop,nop,TS val 167 ecr 0], length 106
E...;4@.@.I.......K.....J^.B,._....,.......
........150 Opening BINARY mode data connection for scenery-backgrounds-6.0.0-1.el6.noarch.rpm (27888036 bytes).

11:39:37.806416 IP 192.168.75.29.37028 > 149.20.20.135.21: Flags [.], ack 3623, win 336, options [nop,nop,TS val 2505518014 ecr 167], length 0
```

Answer: **149.20.20.135.21 > 192.168.75.29.37028**

###Question 4 
 > *4. Difficult: Medium
 
 > Evidence: nfcapd.201405230000 (requires nfdump v1.6.12. Note that nfcapd.201405230000.txt is the same data in nfdump’s “long” output format.)

 > Question: How many IP addresses attempted to connect to destination IP address 63.141.241.10 on the default SSH port?

```
$ egrep "63\.141\.241\.10\:22 " IVS-netflow-2014-05-23/nfcapd.201405230000.txt | awk '{print $5}' | cut -d ":" -f 1 | sort -u | wc -l 
49
```

Answer: **49**

###Question 5 
 > *5. Difficulty: Hard
 
 > Evidence: stark-20120403-full-smb_smb2.pcap
 
 > Question: What is the byte size for the file named “Researched Sub-Atomic Particles.xlsx”
 
End of File: **13625 bytes**

###Question 6 
 > *6. Difficulty: Very Hard
 
 > Evidence: snort.log.1340504390.pcap
 
 > Question: The traffic in this Snort IDS pcap log contains traffic that is suspected to be a malware beaconing. Identify the substring and offset for a common substring that would support a unique Indicator Of Compromise for this activity.

 > Bonus Question: Identify the meaning of the bytes that precede the substring above.

I was able to spot a pattern in Wireshark but some of the repeating characters in the payload did not appear to be valid ascii. I decided to try tshark to see if I could find a pattern with a hexdump. 
```
$ tshark -r snort.log.1340504390.pcap -Tfields -e frame.number -e ip.src -e ip.dst -e data.data
1	10.3.59.24	184.82.188.7	4f:e6:c2:74:55:4c:51:45:4e:50:32:4a:41:44:42:4e:4b:57:47:31:4f:32:4c:4d:42:55:53:52:32:48:4e:0a
2	10.3.59.51	184.82.188.7	4f:e6:c2:75:55:4c:51:45:4e:50:32:46:5a:4c:35:53:56:4b:44:54:46:39:47:34:58:58:45:37:54:46:5a:0a
3	10.3.59.62	184.82.188.7	4f:e6:c2:77:55:4c:51:45:4e:50:32:4d:4d:4c:36:58:43:57:37:53:32:41:38:57:55:45:47:30:32:30:50:0a
4	10.3.59.99	184.82.188.7	4f:e6:c2:78:55:4c:51:45:4e:50:32:48:34:34:52:39:45:4c:36:30:31:42:4a:35:34:39:48:50:49:5a:45:0a
5	10.3.59.9	184.82.188.7	4f:e6:c2:78:55:4c:51:45:4e:50:32:51:59:43:32:54:4c:51:51:4d:36:44:34:35:4c:42:44:46:5a:4b:58:0a
6	10.3.59.30	184.82.188.7	4f:e6:c2:78:55:4c:51:45:4e:50:32:54:4b:34:30:43:50:42:45:56:4b:4f:51:4f:31:42:54:4a:35:51:49:0a
7	10.3.59.195	184.82.188.7	4f:e6:c2:79:55:4c:51:45:4e:50:32:58:5a:34:30:4d:35:43:53:34:44:4b:55:45:57:32:32:55:47:42:35:0a
8	10.3.59.35	184.82.188.7	4f:e6:c2:7a:55:4c:51:45:4e:50:32:4d:59:35:45:5a:57:49:47:42:5a:30:56:49:36:4b:55:48:57:43:50:0a
9	10.3.59.197	184.82.188.7	4f:e6:c2:7a:55:4c:51:45:4e:50:32:55:31:32:4c:32:46:4c:5a:4e:4e:4c:49:34:56:58:36:56:58:31:4f:0a
10	10.3.59.200	184.82.188.7	4f:e6:c2:7b:55:4c:51:45:4e:50:32:47:4e:59:48:44:58:47:38:4d:32:45:58:5a:4b:35:39:39:57:50:48:0a
...
```
After looking at the output I was able to identify the bytes that did not change between packets:
```
4f:e6:XX:XX:55:4c:51:45:4e:50:32:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:0a
```
I decided to use 55:4c:51:45:4e:50:32 as the unique identifier.

The byte offset can be converted from hex:
 > One hexadecimal digit represents a nibble, which is half of an octet or byte (8 bits).
 http://en.wikipedia.org/wiki/Hexadecimal

So the offset would be 4 bytes for 4f:e6:XX:XX.

I used the examples in the Snort 3.5 Payload Detection Rule Options documentation to figure out a good format for the answer. 
http://manual.snort.org/node32.html

Answer: **Content:"|55|4c|51|45|4e|50|32|" Offset: 4 Bytes**

For the bonus question I started looking at the preceding bytes and noticed that the 4th byte changed with the time. 

```
$  tshark -r snort.log.1340504390.pcap -Tfields -e frame.number -e ip.src -e ip.dst -e data.data 
Jun 24, 2012 03:35:32.647890000 290     10.3.59.130     184.82.188.7    4f:e6:c3:44:55:4c:51:45:4e:50:32:55:59:54:39:54:44:39:44:48:31:56:50:4b:35:30:53:4d:56:4f:4e:0a
Jun 24, 2012 03:35:33.233398000 291     10.3.59.157     184.82.188.7    4f:e6:c3:45:55:4c:51:45:4e:50:32:58:45:42:4c:59:36:33:4d:4e:4f:49:5a:55:39:58:42:33:44:46:56:0a
Jun 24, 2012 03:35:34.250709000 292     10.3.59.203     184.82.188.7    4f:e6:c3:46:55:4c:51:45:4e:50:32:4b:34:4b:47:4d:54:4f:43:41:55:31:37:4c:32:52:35:43:39:59:56:0a
Jun 24, 2012 03:35:35.213837000 293     10.3.59.185     184.82.188.7    4f:e6:c3:47:55:4c:51:45:4e:50:32:54:31:57:4f:35:32:34:39:56:50:47:38:46:31:45:56:37:4b:34:30:0a
Jun 24, 2012 03:35:35.218228000 294     10.3.59.12      184.82.188.7    4f:e6:c3:47:55:4c:51:45:4e:50:32:55:4e:51:4a:58:30:45:43:55:53:38:32:51:36:31:5a:57:37:34:31:0a
Jun 24, 2012 03:35:36.015419000 295     10.3.59.129     184.82.188.7    4f:e6:c3:48:55:4c:51:45:4e:50:32:54:35:47:45:42:4a:36:53:56:34:32:39:32:35:34:33:4b:32:52:56:0a
```

After some trial and error (after the due date) I determined that 4f:e6:c3:48 is an epoch time stamp:
```
$ tshark -r snort.log.1340504390.pcap -t e -Tfields -e frame.time_epoch -e data.data | head -n 1
1340523124.786425000	4f:e6:c2:74:55:4c:51:45:4e:50:32:4a:41:44:42:4e:4b:57:47:31:4f:32:4c:4d:42:55:53:52:32:48:4e:0a
$ echo "ibase=16;4FE6C274" | bc
1340523124
```

Bonus Answer: **Epoch Timestamp**

## Other write-ups and resources
* https://blindseeker.com/blahg/?p=281
* http://www.505forensics.com/having-fun-with-the-sans-network-forensics-challenge/

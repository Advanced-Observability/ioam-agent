# IOAM Agent

The IOAM (In-situ Operations, Administration, and Maintenance) agent inspects IPv6 traffic, extracts IOAM trace data, and reports them to an IOAM collector or outputs them locally, to the console or to a file. It currently supports packets with IOAM Hop-by-Hop Option header containing IOAM (Pre-allocated) Trace Option-Type.

## Prerequisites

- [Go](https://go.dev/doc/install) (version 1.25.6 or higher)

- (Optional) **PF_RING**: This application may use PF_RING to capture packets more efficiently. You can install it from [packages](https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html) or from [Git sources](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html).

---

## Building the IOAM Agent

```bash
git clone https://github.com/Advanced-Observability/ioam-agent
cd ioam-agent
make
```

### List of targets

- `make ioam-agent`: Build the IOAM agent.
- `make ioam-agent-pfring`: Build the IOAM agent with PF_RING support.
- `make docker`: Build the Docker image for the IOAM agent.
- `make docker-pfring`: Build the Docker image for the IOAM agent with PF_RING support.
- `make clean`: Clean up executables.

---

## Running the IOAM Agent

1. If using the `ioam-agent-pfring`, ensure that the PF_RING kernel module is loaded.

2. **(Optionally)** Set the environment variable:
  - `IOAM_COLLECTOR`: Specify the IOAM collector socket (`<ip:port>`).

3. **Run the Agent**:
This will capture IOAM traces of packets received on the specified interface:

```bash
./ioam-agent -i <interface name>
```

### List of arguments:
- `-i`: Specify the interface name for packet capture (**mandatory**).
- `-c`: **Reporting Option**: Specify collector socket (`<ip:port>`) for streaming received IOAM traces with gRPC. `IOAM_COLLECTOR` environment variable can also be used (fallback).
- `-d`: **Reporting Option**: Specify file for dumping received IOAM traces in a CSV format.
- `-o`: **Reporting Option**: Print IOAM traces to the console.
- `-s`: Specify log file for exporting agent statistics, rewritten at fixed intervals.
- `-t`: Specify the interval for updating the statistics file (0 disables).
- `-g`: Specify the number of goroutines for parsing the packets (default is 8). This might increase the maximum throughput depending on the system.
- `-h`: Display help.
  
**At least one reporting option must be specified**.

### Examples:
```bash
sudo ./ioam-agent -i eth0 -o
```

```bash
sudo ./ioam-agent-pfring -d ./ioam-traces.csv -i eth1
```

```bash
sudo ./ioam-agent -d ./ioam-traces.csv -s ./agent-stats.log -t 5s -c localhost:7123 -i lo -o
```

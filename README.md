# IOAM Agent

The IOAM (In-situ Operations, Administration, and Maintenance) agent inspects IPv6 traffic, extracts IOAM trace data, and reports them to an IOAM collector or outputs them locally, to the console or to a file. It currently supports packets with IOAM Hop-by-Hop Option header containing IOAM (Pre-allocated) Trace Option-Type.

## Prerequisites

- [Go](https://go.dev/doc/install) (version 1.21 or higher)

- **PF_RING**: This application uses PF_RING to capture packets efficiently. You can install it from [packages](https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html) or from [Git sources](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html).

- [Protocol Buffers (`protoc`)](https://grpc.io/docs/protoc-installation/): Ensure `protoc` is installed with Go support to compile the `.proto` file. You can download it from.

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

2. **Run the Agent**:
    - Capture packets on a specified interface:

    ```bash
    ./ioam-agent -i <interface-name>
    ```

3. **Run the Agent**:
This will capture IOAM traces of packets received on the specified interface:

```bash
./ioam-agent -i <interface name>
```

3. **Logs and Statistics**:
    The agent writes packet statistics (e.g., number of IPv6 and IOAM packets seen) to a file (`./agentStats`). They are updated in real-time.

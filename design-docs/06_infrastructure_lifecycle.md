# Infrastructure & Lifecycle

## 1. Containerized Build Pipeline
To solve the "Ancient Dependencies" problem common in production environments (where the host OS might be Arch but the target is an old Debian), the suite uses an isolated build pipeline.

### Build Image (`release.Dockerfile`)
-   **Base**: Debian Bookworm.
-   **Purpose**: Provides a "Golden Build Server" with exact versions of `clang`, `libbpf`, `libnftables`, and `libcap`.
-   **Isolation**: No host-side libraries are used, ensuring the resulting `.deb` is binary-compatible with target servers.

### The Orchestrator (`release.sh`)
-   **Automated Stage**: Checks for the build image, creates it if necessary, and executes the build inside a transient container.
-   **One-Touch Publishing**: Optionally syncs the resulting repository to Google Cloud Storage.

## 2. Release Engineering
The project's `Makefile` handles the full lifecycle of the software:
1.  **C Binary**: Compiled with hardening flags (`-fPIE`, `-fstack-protector-strong`, `FORTIFY_SOURCE`), linked with `-lcap`.
2.  **Rust Binaries**: `syn-intel` and `syn-sight` are statically compiled using MUSL.
3.  **Debian Package**: `dpkg-buildpackage` bundles binaries, systemd units, man pages, postinst, and configuration files into a standard `.deb`.
4.  **Arch Linux Package**: `archlinux/PKGBUILD` builds the suite via `makepkg`. Uses `musl-gcc` cross-compilation with `kernel-headers-musl` and `vendored-zlib` on `libbpf-sys` for fully static Rust binaries. Includes sysusers/tmpfiles configs and an install script for systemd service management.
5.  **Repository Metadata**: `apt-ftparchive` generates the `Packages` and `Release` files required for `apt-get install` compatibility.

## 3. Operational Best Practices

### Initial Deployment
1.  **Install**: `sudo apt install tcp-syn-stop`.
2.  **Start Services**:
    ```bash
    sudo systemctl enable --now tcp_syn_stop
    sudo systemctl enable --now syn-intel
    ```

### Automated Maintenance Services
-   **ASN + RIR Data Refresh**: `tcp-syn-stop-asn-update.service`/`.timer` runs monthly. Fetches ip2asn TSV and 5 RIR delegation files, imports into SQLite via `syn-intel --import-asn` and `--import-rir`.
-   **Tor Exit Node Blocking**: `tcp-syn-stop-tor-update.service`/`.timer` runs hourly (with 300s random delay). Fetches exit IPs from `check.torproject.org/exit-addresses`, strips old `# tor` tagged entries from `blacklist.conf`, appends fresh ones, sends SIGHUP. Comment tagging (`# tor` suffix) cleanly separates automated entries from manual ones.

### Monitoring & Maintenance
-   **Live View**: Run `sudo syn-sight` for a real-time dashboard.
-   **Audit Logs**:
    ```bash
    journalctl -u tcp_syn_stop -f
    journalctl -u syn-intel -f
    ```
-   **Hot Reload**: If `whitelist.conf` is updated, run `sudo pkill -HUP tcp_syn_stop`.

## 4. Security Posture

### Capability Dropping
The `tcp_syn_stop` daemon drops to `CAP_BPF + CAP_NET_ADMIN` after startup using libcap, and sets `PR_SET_NO_NEW_PRIVS`.

### Service Isolation
-   **`tcp_syn_stop`**: Runs as root (required for XDP attach). Systemd unit enforces `ProtectSystem=strict`, `ReadWritePaths` limited to bpffs and `/opt/tcp_syn_stop`, `NoNewPrivileges`, `PrivateDevices`, `MemoryDenyWriteExecute`, and kernel protection directives.
-   **`syn-intel`**: Runs as dedicated `_syn_intel` system user (created by postinst). `SupplementaryGroups=tcp_syn_stop` for PID file and database access. `AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN`. Same full sandbox as `tcp_syn_stop`.

### User/Group Management
The `tcp-syn-stop.postinst` script creates:
-   System group `tcp_syn_stop` — shared between services for runtime directory and database access.
-   System user `_syn_intel` — dedicated unprivileged user for the policy engine.

### Automatic Recovery
The Systemd Watchdog ensures that any internal deadlock in `tcp_syn_stop` results in a clean process restart within 15 seconds. `syn-intel` uses `Restart=always`.

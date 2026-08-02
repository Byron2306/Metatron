Windows Validation VM

Purpose

Use a dedicated Windows VM to execute Windows-only Atomic Red Team techniques that cannot run inside the Linux sibling sandbox.

What this enables

- Real execution evidence for Windows-only techniques.
- Routing from the backend via the `winrm` runner profile implemented in [backend/atomic_validation.py](../backend/atomic_validation.py).
- Reuse of the same atomic-validation result pipeline and evidence bundle generation.

What this does not solve by itself

- Techniques with no Atomic Red Team test at all.
- Cloud or SaaS techniques that require provider-native accounts and tooling.
- macOS techniques, which still need a macOS host.

Prerequisites

- Either a Windows ISO you are licensed to use or an official Microsoft developer VM archive.
- `sudo` on the Linux host.
- Hardware virtualization available via `/dev/kvm`.

Provision the VM

1. If using an ISO, copy [config/windows_validation_vm.env.example](../config/windows_validation_vm.env.example) to `config/windows_validation_vm.env` and set `WINDOWS_ISO_PATH`.
2. If using the official Microsoft developer VM archive, use [config/windows_validation_vm.env](../config/windows_validation_vm.env) as prepared and wait for the Hyper-V zip download to finish.
3. For the developer VM archive path, convert the Microsoft VHDX into qcow2:

```bash
sudo ./scripts/import_windows_dev_vm.sh
```

4. Create or import the VM:

```bash
sudo ./scripts/setup_windows_validation_vm.sh
```

5. Open the console and complete Windows setup if needed:

```bash
sudo virt-viewer metatron-winval-01
```

Guest setup

Install inside the Windows VM:

- PowerShell 7+
- Atomic Red Team atomics
- Invoke-AtomicRedTeam
- WinRM enabled for remote PowerShell execution

Recommended install paths inside the guest:

- `C:/AtomicRedTeam/atomics`
- `C:/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1`

Wire the backend to the VM

1. Copy the `windows-lab-winrm` profile from [config/atomic_runner_profiles.example.yml](../config/atomic_runner_profiles.example.yml) into [config/atomic_powershell.yml](../config/atomic_powershell.yml).
2. Set `remote_host` to the Windows VM IP from:

```bash
sudo virsh domifaddr metatron-winval-01
```

3. Export the WinRM password used by `password_env` before starting the backend.

Validation approach

- Keep Linux jobs on the `linux-sandbox` profile.
- Add Windows job groups for the remaining Windows techniques and set `runner_profile: windows-lab-winrm`.
- Run those jobs through the existing atomic validation flow.

Current hard blockers in this environment

- The Microsoft developer VM download must finish before import can start.

Current status in this environment

- The QEMU/libvirt/OVMF/swtpm stack is installed.
- An official Microsoft Hyper-V developer VM archive download is in progress under `/home/byron/Downloads/windows-vm-downloads`.
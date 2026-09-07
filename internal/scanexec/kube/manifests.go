package kube

import (
	"fmt"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/aizen299/secure-dev/internal/scanexec"
	"github.com/aizen299/secure-dev/internal/scanners"
)

// Labels applied to everything a scan creates, so a scan's objects can be found
// and deleted as a set, and so a NetworkPolicy can select exactly its own pod.
const (
	LabelScan      = "secureops.io/scan"
	LabelPhase     = "secureops.io/phase"
	LabelManagedBy = "app.kubernetes.io/managed-by"
)

func (e *Executor) objectName(scanID string, phase Phase) string {
	// Kubernetes names are 63 characters and a scan id is a UUID, so this fits
	// with room to spare -- but truncate rather than trust that forever.
	name := fmt.Sprintf("scan-%s-%s", strings.ToLower(scanID), phase)
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimRight(name, "-")
}

func (e *Executor) labels(scanID string, phase Phase) map[string]string {
	return map[string]string{
		LabelScan:      scanID,
		LabelPhase:     string(phase),
		LabelManagedBy: "secureops-controller",
	}
}

// networkPolicy renders what one phase's pod may reach.
//
// Default-deny in both directions, then the minimum. Ingress is always empty:
// nothing in the cluster should ever open a connection TO a scan pod, and a
// scan that accepted one would be a way to reach untrusted content from inside.
func (e *Executor) networkPolicy(req scanexec.Request, phase Phase, egress bool) *networkingv1.NetworkPolicy {
	dns := intstr.FromInt32(53)
	udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP

	rules := []networkingv1.NetworkPolicyEgressRule{
		// DNS, always. Without it a name lookup fails and the failure looks
		// like a broken scanner rather than a policy.
		{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{},
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s-app": "kube-dns"},
				},
			}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Port: &dns, Protocol: &udp}, {Port: &dns, Protocol: &tcp},
			},
		},
		// The controller's intake, and nothing else in the cluster. This is the
		// one hole, and it is a podSelector on one port rather than a CIDR --
		// the scan pod can reach the process that asked for it and no other
		// service, including the database that process talks to.
		e.intakeRule(),
	}

	if egress {
		// The public internet, minus everything private. The cluster network
		// and the link-local address that serves cloud instance credentials are
		// both excluded -- defence in depth behind netguard, which refuses
		// those ranges when a target is validated (T-04, T-49, T-56).
		rules = append(rules, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{
					CIDR:   "0.0.0.0/0",
					Except: privateRanges,
				},
			}},
		})
	}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e.objectName(req.ScanID, phase),
			Namespace: e.opts.Namespace,
			Labels:    e.labels(req.ScanID, phase),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: e.labels(req.ScanID, phase)},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress:  rules,
		},
	}
}

// privateRanges are excluded from a scan pod's internet egress.
var privateRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"127.0.0.0/8",
}

func (e *Executor) intakeRule() networkingv1.NetworkPolicyEgressRule {
	port := intstr.FromInt32(e.opts.IntakePort)
	tcp := corev1.ProtocolTCP
	return networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			PodSelector: &metav1.LabelSelector{MatchLabels: e.opts.IntakeSelector},
		}},
		Ports: []networkingv1.NetworkPolicyPort{{Port: &port, Protocol: &tcp}},
	}
}

// job renders one phase's pod.
//
// Everything a scan is told arrives as an environment variable, and the pod
// holds nothing else: no service account token, no database URL, no Redis URL.
// A compromised scanner gets a channel to one scan's results and a directory
// that dies with it.
func (e *Executor) job(req scanexec.Request, phase Phase, token string, egress bool) *batchv1.Job {
	name := e.objectName(req.ScanID, phase)
	labels := e.labels(req.ScanID, phase)
	falsePtr := false
	truePtr := true
	user := int64(65532)
	backoff := int32(0)
	ttl := e.opts.TTLSeconds

	env := []corev1.EnvVar{
		{Name: "SECUREOPS_JOB_SCAN_ID", Value: req.ScanID},
		{Name: "SECUREOPS_JOB_PROJECT_ID", Value: req.ProjectID},
		{Name: "SECUREOPS_JOB_CALLBACK_URL", Value: e.opts.CallbackURL},
		{Name: "SECUREOPS_JOB_TOKEN", Value: token},
		{Name: "SECUREOPS_JOB_PHASE", Value: string(phase)},
		{Name: "SECUREOPS_JOB_TARGET_KIND", Value: string(req.Target.Kind)},
		{Name: "SECUREOPS_JOB_TARGET_REPOSITORY_URL", Value: req.Target.RepositoryURL},
		{Name: "SECUREOPS_JOB_TARGET_REF", Value: req.Target.Ref},
		{Name: "SECUREOPS_JOB_TARGET_IMAGE", Value: req.Target.Image},
		{Name: "SECUREOPS_JOB_TARGET_ENDPOINT_URL", Value: req.Target.EndpointURL},
		{Name: "SECUREOPS_JOB_SCANNERS", Value: strings.Join(names(req.Scanners), ",")},
		{Name: "SECUREOPS_WORKSPACE_ROOT", Value: workspaceMount},
		// Deliberately absent: SECUREOPS_DATABASE_URL and SECUREOPS_REDIS_URL.
		// The whole point of ADR 039 is that this pod cannot reach either.
	}

	mounts := []corev1.VolumeMount{
		{Name: "workspace", MountPath: workspaceMount},
		{Name: "tmp", MountPath: "/tmp"},
	}
	volumes := []corev1.Volume{
		{
			Name: "workspace",
			VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: e.workspaceClaim(req.ScanID),
			}},
		},
		{
			Name: "tmp",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
				SizeLimit: quantity(e.opts.TmpSize),
			}},
		},
	}

	// The vulnerability database, read-only, shared (ADR 039 §6). Only the
	// scanning phase needs it, and it cannot be written by the pod that runs
	// untrusted binaries.
	if phase == PhaseScan && e.opts.VulnDBClaim != "" {
		mounts = append(mounts, corev1.VolumeMount{
			Name: "vulndb", MountPath: e.opts.VulnDBMountPath, ReadOnly: true,
		})
		volumes = append(volumes, corev1.Volume{
			Name: "vulndb",
			VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: e.opts.VulnDBClaim, ReadOnly: true,
			}},
		})
		env = append(env, corev1.EnvVar{
			Name: "SECUREOPS_GRYPE_DB_DIR", Value: e.opts.VulnDBMountPath,
		})
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.opts.Namespace, Labels: labels},
		Spec: batchv1.JobSpec{
			// No retries. A scan that failed is a scan the controller records
			// as failed; silently running an attacker's repository a second
			// time is not a recovery strategy.
			BackoffLimit: &backoff,
			// The Job object cleans itself up even if the controller dies
			// between creating it and deleting it.
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					// THE line. A compromised scanner cannot even ask the API
					// server who it is, let alone create anything.
					AutomountServiceAccountToken: &falsePtr,
					ServiceAccountName:           e.opts.JobServiceAccount,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   &truePtr,
						RunAsUser:      &user,
						RunAsGroup:     &user,
						FSGroup:        &user,
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            string(phase),
						Image:           e.opts.JobImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"/usr/local/bin/scanjob"},
						Env:             env,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falsePtr,
							ReadOnlyRootFilesystem:   &truePtr,
							Privileged:               &falsePtr,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						Resources:    e.opts.Resources,
						VolumeMounts: mounts,
					}},
					Volumes: volumes,
				},
			},
		},
	}
}

const workspaceMount = "/workspaces"

// workspaceClaim names the per-scan volume the two phases share.
//
// A claim rather than an emptyDir, because a repository's checkout has to
// survive the fetch pod ending and be readable by the scan pod. Its size is the
// bound that closes T-51: a layer that decompresses past it fills a volume that
// dies with the scan, rather than the node's disk.
func (e *Executor) workspaceClaim(scanID string) string {
	return e.objectName(scanID, "workspace")
}

func (e *Executor) workspacePVC(req scanexec.Request) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e.workspaceClaim(req.ScanID),
			Namespace: e.opts.Namespace,
			Labels:    e.labels(req.ScanID, "workspace"),
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: storageClass(e.opts.WorkspaceStorageClass),
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: *quantity(e.opts.WorkspaceSize),
				},
			},
		},
	}
}

func storageClass(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func quantity(s string) *resource.Quantity {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		// Options are validated at construction, so this is unreachable; a
		// zero quantity would silently mean "unbounded", which is the one
		// outcome a size limit must never have.
		panic(fmt.Sprintf("kube: unparseable quantity %q: %v", s, err))
	}
	return &q
}

func names(sc []scanners.Scanner) []string {
	out := make([]string, 0, len(sc))
	for _, s := range sc {
		out = append(out, s.Name())
	}
	return out
}

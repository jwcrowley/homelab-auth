
Install Tetragon:

helm repo add cilium https://helm.cilium.io/

helm install tetragon cilium/tetragon   --namespace kube-system

Tetragon provides:
- Process execution enforcement
- File access monitoring
- Network runtime policy enforcement
- eBPF-based syscall filtering

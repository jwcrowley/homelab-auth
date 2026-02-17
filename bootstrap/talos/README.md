
Talos Linux Alternative:

talosctl gen config homelab https://<control-plane-ip>:6443

Apply configs:
talosctl apply-config --insecure -n <node-ip> -f controlplane.yaml

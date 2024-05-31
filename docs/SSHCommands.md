ssh-keygen -L -f roles/pi-base/nopush/ssh_host_rsa_key-cert.pub
  276  ssh -vv -i ./user-key <ip> | grep "Server host certificate"
  277  ssh -vv -i ./user-key  <ip> 2>&1 | grep "Server host certificate"
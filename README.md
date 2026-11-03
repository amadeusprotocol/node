# node

### Tested Distro/Env
Linux Kernel 6.8  
Ubuntu 24.04  

### Building
Using podman or docker
```
podman build --tag erlang_builder -f build.Dockerfile
./build.sh
```

### Testnet
```
#run local testnet with RPC api

#point RPC endpoint to localhost
vim /etc/hosts
127.0.0.1 nodes.amadeus.bot

#run google chrome with cert verification disabled and CORS disabled
mkdir -p /tmp/chrome_debug
google-chrome  --user-data-dir="/tmp/chrome_debug" --no-first-run --no-default-browser-check \
--ignore-certificate-errors --disable-web-security --unsafely-treat-insecure-origin-as-secure=https://nodes.amadeus.bot

#allow listening on port 80 and 443
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80

#run the local testnet
TESTNET=true WORKFOLDER=/tmp/testnet HTTP_IPV4=127.0.0.1 HTTP_PORT=80  ./amadeusd

# inside REPL submit a transfer to self
pk = Application.fetch_env!(:ama, :trainer_pk)
sk = Application.fetch_env!(:ama, :trainer_sk)
Testnet.call(sk, "Coin", "transfer", [pk,"1","AMA"])

# Deploy contract (default account is :trainer_pk)

pk = Application.fetch_env!(:ama, :trainer_pk)
sk = Application.fetch_env!(:ama, :trainer_sk)
Testnet.deploy "/home/user/project/node/contract_samples/riscv/out/counter.elf"
Testnet.call sk, pk, "get", []
Testnet.call sk, pk, "inc", ["2"]
```

### AutoUpdates + Running as a systemd service

```
cat <<EOT > /etc/sysctl.conf
#buff up the UDP stack for 1gbps
net.core.wmem_max = 268435456
net.core.rmem_default = 212992
net.core.rmem_max = 268435456
net.core.netdev_max_backlog = 300000
net.core.optmem_max = 16777216
net.ipv4.udp_mem = 3060432 4080578 6120864

# for normal networks: block spoofed UDP packets
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
EOT
```

```
cat <<EOT > /etc/security/limits.conf
root hard nofile 1048576
root soft nofile 1048576
* hard nofile 1048576
* soft nofile 1048576
root hard nproc unlimited
root soft nproc unlimited
* hard nproc unlimited
* soft nproc unlimited
root hard memlock unlimited
root soft memlock unlimited
* hard memlock unlimited
* soft memlock unlimited
EOT
cat <<EOT > /etc/systemd/system.conf
[Manager]
DefaultTasksMax=infinity
DefaultLimitNOFILE=infinity
DefaultLimitNPROC=infinity
DefaultLimitMEMLOCK=infinity
DefaultLimitLOCKS=infinity
EOT
cat <<EOT > /etc/systemd/user.conf
[Manager]
DefaultTasksMax=infinity
DefaultLimitNOFILE=infinity
DefaultLimitNPROC=infinity
DefaultLimitMEMLOCK=infinity
DefaultLimitLOCKS=infinity
EOT


cat <<EOT > /etc/systemd/system/amadeusd.service
[Unit]
Description=AmadeusD
After=network-online.target

[Service]
Type=forking
LimitNOFILE=1048576
KillMode=control-group
Restart=always
RestartSec=3
User=root
WorkingDirectory=/root/
Environment="AUTOUPDATE=true"
ExecStart=/usr/bin/screen -UdmS amadeusd bash -c './amadeusd'

[Install]
WantedBy=default.target
EOT

systemctl enable amadeusd
systemctl start amadeusd

screen -rd amadeusd
```

For non-root change:
```
WorkingDirectory=/home/youruser
User=youruser
```

```
For computor autostart
Environment="COMPUTOR=true"

For computor autostart to be validator
Environment="COMPUTOR=trainer"
```

<sub>
Disclaimer: This is an open-source research project shared for educational and informational purposes only. All code, content, and related materials are provided “as is”, with no guarantees or warranties. This project is experimental, may change over time, and may contain errors. You use this code at your own risk. The contributors and maintainers are not responsible for any loss, damage, or legal issues resulting from its use. You are responsible for following all laws and regulations in your location. Use in or by sanctioned countries, individuals, or organizations, such as those restricted under U.S. export laws or OFAC rules, is strictly prohibited. We do not support or encourage the unlawful or unauthorized deployment of this code.
</sub>

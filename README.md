
# Kaminsky DNS Cache Poisoning Attack Lab

This repository contains the code and executables used to launch a Kaminsky DNS cache poisoning attack. This code was written as part of a homework assignment based on the ["Remote DNS Attack" SEED Lab](https://seedsecuritylabs.org/Labs_16.04/Networking/DNS_Remote/).

## Overview

The Kaminsky attack works by submitting a DNS query for a non-existent subdomain of the target domain (e.g., `ksdgb.example.com` if trying to control resolution for the `example.com` domain). The attacker then sends spoofed DNS responses with an authoritative NS record for the target domain. If successful, the target DNS resolver will cache the incorrect NS entry, effectively allowing the attacker to redirect any traffic (relying on the poisoned resolver) meant for the target domain to an IP address controlled by the attacker.

## Prerequisites

Before starting the lab, ensure you have the following installed:
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- Basic understanding of DNS and networking.

## Installation and Setup

### Step 1: Clone the Repository
First, clone this repository to your local machine:
```bash
git clone https://github.com/elilfry/Syber_Lab_Kaminsky_Attack.git
cd kaminsky-attack-lab
```

### Step 2: Start Docker Containers
Next, you’ll need to start the Docker containers that simulate the DNS servers (attacker and victim) and user machines. Use the following commands:

```bash
sudo docker-compose up -d
```

This will bring up four containers:
1. **Local DNS Server** (`local-dns-server-10.9.0.53`)
2. **User Machine** (`user-10.9.0.5`)
3. **Attacker Name Server (NS)** (`attacker-ns-10.9.0.153`)
4. **Seed Attacker** (`seed-attacker`)

To verify the containers are running, use:
```bash
sudo docker ps -a
```

### Step 3: Access the Containers
To start interacting with the containers, you’ll need to get inside them using `docker exec`. Here are the commands for each container:

- Local DNS Server (`local-dns-server-10.9.0.53`):
  ```bash
  sudo docker exec -it 65 /bin/bash
  export PS1="local-dns-server-10.9.0.53:\w\n\$> "
  ```

- User Machine (`user-10.9.0.5`):
  ```bash
  sudo docker exec -it b9 /bin/bash
  export PS1="user-10.9.0.5:\w\n\$> "
  ```

- Attacker NS (`attacker-ns-10.9.0.153`):
  ```bash
  sudo docker exec -it b3 /bin/bash
  export PS1="attacker-ns-10.9.0.153:\w\n\$> "
  ```

- Seed Attacker (`seed-attacker`):
  ```bash
  sudo docker exec -it 40 /bin/bash
  export PS1="seed-attacker:\w\n\$> "
  ```

### Step 4: Running DNS Queries
Once you’re inside the **User Machine**, you can run the following DNS queries to simulate a normal user:

1. Query the attacker’s DNS server:
   ```bash
   dig ns.attacker32.com
   ```

2. Query `www.example.com`:
   ```bash
   dig www.example.com
   ```

3. Query `NS` for `www.example.com`:
   ```bash
   dig ns www.example.com
   ```

4. Query `www.example.com` directly from the attacker’s NS server:
   ```bash
   dig @ns.attacker32.com www.example.com
   ```

5. Query `www.example.com` from the attacker's IP:
   ```bash
   dig @10.9.0.153 www.example.com
   ```

### Step 5: Prepare DNS Spoofing Tools
To prepare the DNS servers, log into the **Local DNS Server NS** machine and install `tcpdump` to capture network packets:
```bash
sudo apt-get update
sudo apt-get install tcpdump
```

### Step 6: Clear DNS Cache
Flush the cache on the local DNS server to ensure no old queries interfere with the attack:
```bash
rndc flush
```

### Step 7: Launching the Attack
Now you can run the attack from the **Seed Attacker** machine. Use the provided scripts or commands to simulate the Kaminsky attack and inject false DNS responses to poison the cache of the **Local DNS Server**.

---

All you need to do to launch the Kaminsky DNS Cache Poisoning attack is to navigate into the `volumes` directory in **Seed Attacker** machine and execute the `make` command. This will run the provided scripts and C program to initiate the attack.

```bash
cd volumes
make
```

This command will compile the `attack.c` file and run the two Python scripts (`DNS_Request2.py` and `Spoof_DNS_Replies3.py`) that are responsible for generating DNS requests and spoofing DNS replies. The attack will then start, targeting the local DNS server and attempting to poison its cache.

Make sure that the Docker containers are up and running before executing the `make` command.

---

### Python Scripts
- `DNS_Request2.py`: Script to send DNS queries to the local DNS server.
- `Spoof_DNS_Replies3.py`: Script to spoof DNS replies and redirect the query results.

## Verifying the Attack
Once the attack is completed, verify if the DNS cache was poisoned by dumping the DNS cache on the **Local DNS Server** and searching for the attacker’s domain in the cache:

```bash
rndc dumpdb -cache && grep attacker /var/cache/bind/dump.db
```

If the output contains the attacker’s domain (`attacker32.com`) in the cache entries, the attack was successful.

---

## Conclusion

This lab demonstrates the Kaminsky DNS Cache Poisoning attack, a real-world vulnerability exploited to poison the DNS cache of recursive DNS resolvers. By following this lab, you will gain a practical understanding of how DNS poisoning works and how such attacks can be mitigated in modern networks.

---


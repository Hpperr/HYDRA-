# Scan network only
sudo python3 hydra.py -i eth0 --scan

# Attack specific target
sudo python3 hydra.py -i eth0 --target 192.168.1.100

# Configuration file: config.json
{
  "interfaces": {
    "capture": "eth0",
    "replay": "eth1"
  },
  "pcap_dir": "./pcaps",
  "results_dir": "./replay_results",
  "tools": {
    "tcpreplay_path": "/usr/bin/tcpreplay",
    "tcprewrite_path": "/usr/bin/tcprewrite",
    "tshark_path": "/usr/bin/tshark",
    "tcpdump_path": "/usr/bin/tcpdump"
  },
  "ids_integration": {
    "alert_log": "/var/log/suricata/fast.log",
    "monitoring_enabled": true,
    "alert_patterns": ["ALERT", "WARNING", "DROP"]
  },
  "anonymization": {
    "enabled": false,
    "preserve_subnet_structure": true,
    "anonymize_ports": false
  }
}

# Example experiment configuration: malware_detection_test.json
{
  "name": "malware_detection_baseline",
  "description": "Test IDS detection of malware traffic at various rates",
  "pcap_file": "./pcaps/malware_sample.pcap",
  "expected_alerts": ["MALWARE", "TROJAN"],
  "rewrite_options": {
    "src_ip": "10.0.1.100",
    "dst_ip": "10.0.1.200",
    "fix_checksums": true
  },
  "replay_configs": [
    {
      "name": "original_timing",
      "multiplier": 1.0,
      "description": "Replay at original packet timing"
    },
    {
      "name": "slow_replay", 
      "multiplier": 0.1,
      "description": "10x slower than original"
    },
    {
      "name": "fast_replay",
      "multiplier": 10.0,
      "description": "10x faster than original"
    },
    {
      "name": "rate_limited",
      "pps": 1000,
      "description": "Fixed 1000 packets per second"
    }
  ],
  "delay_between_replays": 30,
  "ids_monitoring": {
    "enabled": true,
    "pre_replay_delay": 5,
    "post_replay_delay": 10
  }
}

# Flow extraction configuration: flow_filters.json
{
  "malware_flows": [
    {
      "name": "http_malware",
      "filter": "http and tcp.payload contains \"malware\"",
      "description": "HTTP traffic containing malware signatures"
    },
    {
      "name": "dns_tunneling",
      "filter": "dns and frame.len > 512",
      "description": "Large DNS queries potentially indicating tunneling"
    },
    {
      "name": "port_scan",
      "filter": "tcp.flags.syn == 1 and tcp.flags.ack == 0",
      "description": "TCP SYN packets for port scan detection"
    }
  ],
  "benign_flows": [
    {
      "name": "normal_http",
      "filter": "http and not tcp.payload contains \"malware\"",
      "description": "Normal HTTP traffic"
    },
    {
      "name": "normal_dns", 
      "filter": "dns and frame.len < 256",
      "description": "Normal DNS queries"
    }
  ]
}

# Installation script: install_dependencies.sh
#!/bin/bash

echo "Installing Packet Replay Toolkit Dependencies..."

# Update package manager
sudo apt-get update

# Install required packages
sudo apt-get install -y \
    tcpreplay \
    tshark \
    wireshark-common \
    tcpdump \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    libpcap-dev

# Install Python packages
pip3 install \
    scapy \
    pyshark \
    pandas \
    matplotlib \
    seaborn

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Verify installations
echo "Verifying installations..."
tcpreplay --version
tshark --version
tcpdump --version

# Set up permissions for packet capture (optional)
echo "Setting up packet capture permissions..."
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
sudo usermod -a -G wireshark $USER

echo "Installation complete!"
echo "Please log out and back in to apply group changes."

# Quick start script: quick_start.sh
#!/bin/bash

echo "Packet Replay Toolkit - Quick Start"
echo "==================================="

# Check if toolkit is available
if [ ! -f "packet_replay_toolkit.py" ]; then
    echo "Error: packet_replay_toolkit.py not found!"
    exit 1
fi

# Create sample configuration if it doesn't exist
if [ ! -f "config.json" ]; then
    echo "Creating default configuration..."
    cat > config.json << 'EOF'
{
  "interfaces": {
    "capture": "eth0",
    "replay": "eth1"
  },
  "pcap_dir": "./pcaps",
  "results_dir": "./replay_results"
}
EOF
fi

# Create directories
mkdir -p pcaps replay_results

echo ""
echo "Usage Examples:"
echo "==============="
echo ""
echo "1. Capture traffic for 60 seconds:"
echo "   python3 packet_replay_toolkit.py --capture 60 --filter 'tcp port 80'"
echo ""
echo "2. Extract flows from existing pcap:"
echo "   python3 packet_replay_toolkit.py --extract ./pcaps/sample.pcap"
echo ""
echo "3. Replay a pcap file:"
echo "   python3 packet_replay_toolkit.py --replay ./pcaps/sample.pcap"
echo ""
echo "4. Analyze a pcap file:"
echo "   python3 packet_replay_toolkit.py --analyze ./pcaps/sample.pcap"
echo ""
echo "5. Generate test scenarios:"
echo "   python3 packet_replay_toolkit.py --generate-scenarios ./pcaps/sample.pcap"
echo ""
echo "6. Run an experiment:"
echo "   python3 packet_replay_toolkit.py --experiment experiment_config.json"
echo ""

# Network setup helper script: setup_lab.sh
#!/bin/bash

echo "Setting up packet replay lab environment..."

# Function to create network namespaces for isolated testing
setup_namespaces() {
    echo "Creating network namespaces..."
    
    # Create namespaces
    sudo ip netns add replay-source
    sudo ip netns add replay-target
    sudo ip netns add ids-monitor
    
    # Create virtual ethernet pairs
    sudo ip link add veth-src type veth peer name veth-src-peer
    sudo ip link add veth-tgt type veth peer name veth-tgt-peer
    sudo ip link add veth-mon type veth peer name veth-mon-peer
    
    # Assign interfaces to namespaces
    sudo ip link set veth-src netns replay-source
    sudo ip link set veth-tgt netns replay-target
    sudo ip link set veth-mon netns ids-monitor
    
    # Configure IP addresses
    sudo ip netns exec replay-source ip addr add 192.168.1.10/24 dev veth-src
    sudo ip netns exec replay-target ip addr add 192.168.1.20/24 dev veth-tgt
    sudo ip netns exec ids-monitor ip addr add 192.168.1.30/24 dev veth-mon
    
    # Bring interfaces up
    sudo ip netns exec replay-source ip link set veth-src up
    sudo ip netns exec replay-target ip link set veth-tgt up
    sudo ip netns exec ids-monitor ip link set veth-mon up
    
    echo "Network namespaces configured successfully"
}

# Function to setup traffic mirroring
setup_mirroring() {
    echo "Setting up traffic mirroring..."
    
    # Create a bridge for traffic mirroring
    sudo brctl addbr replay-bridge
    sudo ip link set replay-bridge up
    
    # Add interfaces to bridge
    sudo brctl addif replay-bridge veth-src-peer
    sudo brctl addif replay-bridge veth-tgt-peer
    sudo brctl addif replay-bridge veth-mon-peer
    
    echo "Traffic mirroring configured"
}

# Main setup function
main() {
    case $1 in
        "namespaces")
            setup_namespaces
            ;;
        "mirroring")
            setup_mirroring
            ;;
        "full")
            setup_namespaces
            setup_
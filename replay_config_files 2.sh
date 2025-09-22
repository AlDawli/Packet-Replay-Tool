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
            setup_mirroring
            echo "Full lab environment setup complete"
            ;;
        "cleanup")
            cleanup_lab
            ;;
        *)
            echo "Usage: $0 {namespaces|mirroring|full|cleanup}"
            echo ""
            echo "  namespaces - Create isolated network namespaces"
            echo "  mirroring  - Setup traffic mirroring bridge"  
            echo "  full       - Complete lab setup"
            echo "  cleanup    - Remove lab environment"
            ;;
    esac
}

# Cleanup function
cleanup_lab() {
    echo "Cleaning up lab environment..."
    
    # Remove namespaces
    sudo ip netns del replay-source 2>/dev/null
    sudo ip netns del replay-target 2>/dev/null
    sudo ip netns del ids-monitor 2>/dev/null
    
    # Remove bridge
    sudo ip link set replay-bridge down 2>/dev/null
    sudo brctl delbr replay-bridge 2>/dev/null
    
    # Remove remaining veth pairs
    sudo ip link del veth-src-peer 2>/dev/null
    sudo ip link del veth-tgt-peer 2>/dev/null
    sudo ip link del veth-mon-peer 2>/dev/null
    
    echo "Lab environment cleaned up"
}

main $1

# Performance testing script: performance_test.sh
#!/bin/bash

echo "Packet Replay Performance Testing"
echo "================================="

PCAP_FILE="$1"
if [ -z "$PCAP_FILE" ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file not found: $PCAP_FILE"
    exit 1
fi

echo "Testing with PCAP file: $PCAP_FILE"

# Test different replay speeds
SPEEDS=(0.1 0.5 1.0 2.0 5.0 10.0)
RESULTS_FILE="performance_results_$(date +%Y%m%d_%H%M%S).csv"

echo "speed_multiplier,packets_sent,bytes_sent,elapsed_time,pps,mbps,cpu_percent" > "$RESULTS_FILE"

for speed in "${SPEEDS[@]}"; do
    echo ""
    echo "Testing at ${speed}x speed..."
    
    # Start CPU monitoring in background
    (top -b -n1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//') > /tmp/cpu_before &
    
    # Run tcpreplay with timing
    START_TIME=$(date +%s.%N)
    
    REPLAY_OUTPUT=$(tcpreplay --intf1=eth1 --multiplier="$speed" --stats=1 "$PCAP_FILE" 2>&1)
    REPLAY_EXIT_CODE=$?
    
    END_TIME=$(date +%s.%N)
    ELAPSED=$(echo "$END_TIME - $START_TIME" | bc)
    
    # Get CPU usage
    CPU_USAGE=$(cat /tmp/cpu_before 2>/dev/null || echo "0")
    
    if [ $REPLAY_EXIT_CODE -eq 0 ]; then
        # Parse tcpreplay output
        PACKETS=$(echo "$REPLAY_OUTPUT" | grep -oP 'Actual: \K\d+(?= packets)')
        BYTES=$(echo "$REPLAY_OUTPUT" | grep -oP 'Actual: \d+ packets \(\K\d+(?= bytes)')
        
        if [ -n "$PACKETS" ] && [ -n "$BYTES" ] && [ -n "$ELAPSED" ]; then
            PPS=$(echo "scale=2; $PACKETS / $ELAPSED" | bc)
            MBPS=$(echo "scale=2; ($BYTES * 8) / ($ELAPSED * 1000000)" | bc)
            
            echo "$speed,$PACKETS,$BYTES,$ELAPSED,$PPS,$MBPS,$CPU_USAGE" >> "$RESULTS_FILE"
            echo "  Packets: $PACKETS, Rate: $PPS pps, $MBPS Mbps"
        else
            echo "  Failed to parse output"
        fi
    else
        echo "  Replay failed at ${speed}x speed"
    fi
    
    # Clean up temp files
    rm -f /tmp/cpu_before
    
    # Wait between tests
    sleep 2
done

echo ""
echo "Performance test complete. Results saved to: $RESULTS_FILE"

# Generate performance report
python3 << 'EOF'
import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

results_file = [f for f in os.listdir('.') if f.startswith('performance_results_') and f.endswith('.csv')]
if not results_file:
    print("No results file found")
    sys.exit(1)

df = pd.read_csv(results_file[-1])  # Use most recent file

# Create performance plots
fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 8))

# Packets per second vs speed multiplier
ax1.plot(df['speed_multiplier'], df['pps'], 'b-o')
ax1.set_xlabel('Speed Multiplier')
ax1.set_ylabel('Packets/sec')
ax1.set_title('Throughput vs Speed')
ax1.grid(True)

# Throughput in Mbps
ax2.plot(df['speed_multiplier'], df['mbps'], 'r-o')
ax2.set_xlabel('Speed Multiplier')
ax2.set_ylabel('Mbps')
ax2.set_title('Bandwidth vs Speed')
ax2.grid(True)

# CPU usage
ax3.plot(df['speed_multiplier'], df['cpu_percent'], 'g-o')
ax3.set_xlabel('Speed Multiplier')
ax3.set_ylabel('CPU %')
ax3.set_title('CPU Usage vs Speed')
ax3.grid(True)

# Efficiency (packets per CPU %)
efficiency = df['pps'] / (df['cpu_percent'] + 0.1)  # Avoid division by zero
ax4.plot(df['speed_multiplier'], efficiency, 'm-o')
ax4.set_xlabel('Speed Multiplier')
ax4.set_ylabel('Packets/sec per CPU%')
ax4.set_title('Efficiency vs Speed')
ax4.grid(True)

plt.tight_layout()
plt.savefig('performance_analysis.png', dpi=300, bbox_inches='tight')
print(f"Performance analysis saved to: performance_analysis.png")

# Print summary statistics
print("\nPerformance Summary:")
print("===================")
print(f"Maximum throughput: {df['pps'].max():.0f} pps at {df.loc[df['pps'].idxmax(), 'speed_multiplier']}x speed")
print(f"Maximum bandwidth: {df['mbps'].max():.2f} Mbps at {df.loc[df['mbps'].idxmax(), 'speed_multiplier']}x speed")
print(f"Best efficiency: {efficiency.max():.0f} pps/CPU% at {df.loc[efficiency.idxmax(), 'speed_multiplier']}x speed")
EOF

# IDS Alert monitoring script: monitor_ids.py
#!/usr/bin/env python3
"""
IDS Alert Monitor for Packet Replay Testing
Monitors IDS logs during replay tests and correlates alerts with replay timing
"""

import time
import json
import csv
import argparse
import threading
from datetime import datetime
from pathlib import Path
import subprocess
import re

class IDSMonitor:
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file)
        self.alerts = []
        self.monitoring = False
        self.monitor_thread = None
        
    def load_config(self, config_file):
        default_config = {
            "alert_log": "/var/log/suricata/fast.log",
            "alert_patterns": ["ALERT", "WARNING", "DROP"],
            "output_dir": "./replay_results/alerts"
        }
        
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config.get('ids_integration', {}))
        
        return default_config
    
    def start_monitoring(self, experiment_name):
        """Start monitoring IDS alerts"""
        self.experiment_name = experiment_name
        self.alerts = []
        self.monitoring = True
        
        # Create output directory
        output_dir = Path(self.config['output_dir'])
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        print(f"Started IDS monitoring for experiment: {experiment_name}")
    
    def stop_monitoring(self):
        """Stop monitoring and save results"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        # Save alerts to file
        self._save_alerts()
        
        print(f"Stopped IDS monitoring. Captured {len(self.alerts)} alerts.")
        return self.alerts
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        log_file = Path(self.config['alert_log'])
        
        if not log_file.exists():
            print(f"Warning: Alert log file not found: {log_file}")
            return
        
        # Use tail -f to follow the log file
        cmd = ['tail', '-f', str(log_file)]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, 
                                     universal_newlines=True)
            
            while self.monitoring:
                line = process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # Check if line contains any alert patterns
                for pattern in self.config['alert_patterns']:
                    if pattern.lower() in line.lower():
                        alert = {
                            'timestamp': datetime.now().isoformat(),
                            'raw_line': line.strip(),
                            'pattern_matched': pattern,
                            'experiment': self.experiment_name
                        }
                        
                        # Try to extract more details from the alert
                        alert.update(self._parse_alert(line))
                        self.alerts.append(alert)
                        break
            
            process.terminate()
            
        except Exception as e:
            print(f"Error monitoring alerts: {e}")
    
    def _parse_alert(self, alert_line):
        """Parse alert line to extract structured information"""
        alert_info = {}
        
        # Common patterns for different IDS systems
        patterns = {
            'suricata': r'\[(?P<timestamp>\d+/\d+/\d+-\d+:\d+:\d+\.\d+)\].*?\[(?P<classification>.*?)\].*?(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) -> (?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)',
            'snort': r'\d+/\d+/\d+-\d+:\d+:\d+\.\d+ +(?P<message>.*?) +(?P<src_ip>\d+\.\d+\.\d+\.\d+):?(?P<src_port>\d*) -> (?P<dst_ip>\d+\.\d+\.\d+\.\d+):?(?P<dst_port>\d*)',
        }
        
        for ids_type, pattern in patterns.items():
            match = re.search(pattern, alert_line)
            if match:
                alert_info.update(match.groupdict())
                alert_info['ids_type'] = ids_type
                break
        
        return alert_info
    
    def _save_alerts(self):
        """Save alerts to JSON and CSV files"""
        if not self.alerts:
            return
        
        output_dir = Path(self.config['output_dir'])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save as JSON
        json_file = output_dir / f"{self.experiment_name}_alerts_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.alerts, f, indent=2)
        
        # Save as CSV
        csv_file = output_dir / f"{self.experiment_name}_alerts_{timestamp}.csv"
        if self.alerts:
            fieldnames = set()
            for alert in self.alerts:
                fieldnames.update(alert.keys())
            
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=list(fieldnames))
                writer.writeheader()
                writer.writerows(self.alerts)
        
        print(f"Alerts saved to: {json_file} and {csv_file}")
    
    def analyze_alerts(self, replay_timestamps):
        """Analyze alerts in context of replay timing"""
        analysis = {
            'total_alerts': len(self.alerts),
            'alerts_during_replay': 0,
            'alert_types': {},
            'timeline': []
        }
        
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            
            # Check if alert occurred during any replay
            during_replay = False
            for replay in replay_timestamps:
                start_time = datetime.fromisoformat(replay['start'])
                end_time = datetime.fromisoformat(replay['end'])
                
                if start_time <= alert_time <= end_time:
                    during_replay = True
                    analysis['alerts_during_replay'] += 1
                    alert['replay_context'] = replay
                    break
            
            # Count alert types
            pattern = alert.get('pattern_matched', 'unknown')
            analysis['alert_types'][pattern] = analysis['alert_types'].get(pattern, 0) + 1
            
            # Add to timeline
            analysis['timeline'].append({
                'timestamp': alert['timestamp'],
                'during_replay': during_replay,
                'pattern': pattern
            })
        
        return analysis

def main():
    parser = argparse.ArgumentParser(description="IDS Alert Monitor")
    parser.add_argument('--config', help='Configuration file')
    parser.add_argument('--experiment', required=True, help='Experiment name')
    parser.add_argument('--duration', type=int, default=60, help='Monitoring duration in seconds')
    
    args = parser.parse_args()
    
    monitor = IDSMonitor(args.config)
    
    print(f"Starting IDS monitoring for {args.duration} seconds...")
    monitor.start_monitoring(args.experiment)
    
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\nStopping monitoring due to interrupt...")
    
    alerts = monitor.stop_monitoring()
    print(f"Monitoring complete. Captured {len(alerts)} alerts.")

if __name__ == "__main__":
    main()

# Validation and testing script: validate_setup.sh
#!/bin/bash

echo "Packet Replay Toolkit - Setup Validation"
echo "========================================"

ERRORS=0

# Function to check if command exists
check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        echo "✓ $1 found"
    else
        echo "✗ $1 not found"
        ERRORS=$((ERRORS + 1))
    fi
}

# Function to check if file exists
check_file() {
    if [ -f "$1" ]; then
        echo "✓ $1 exists"
    else
        echo "✗ $1 not found"
        ERRORS=$((ERRORS + 1))
    fi
}

# Check required commands
echo "Checking required tools..."
check_command tcpreplay
check_command tcprewrite  
check_command tshark
check_command tcpdump
check_command python3

# Check Python packages
echo ""
echo "Checking Python packages..."
python3 -c "import json; print('✓ json module available')" 2>/dev/null || { echo "✗ json module not available"; ERRORS=$((ERRORS + 1)); }
python3 -c "import csv; print('✓ csv module available')" 2>/dev/null || { echo "✗ csv module not available"; ERRORS=$((ERRORS + 1)); }
python3 -c "import subprocess; print('✓ subprocess module available')" 2>/dev/null || { echo "✗ subprocess module not available"; ERRORS=$((ERRORS + 1)); }

# Check optional packages
echo ""
echo "Checking optional Python packages..."
python3 -c "import scapy; print('✓ scapy available')" 2>/dev/null || echo "! scapy not available (optional)"
python3 -c "import pyshark; print('✓ pyshark available')" 2>/dev/null || echo "! pyshark not available (optional)"
python3 -c "import pandas; print('✓ pandas available')" 2>/dev/null || echo "! pandas not available (optional)"

# Check toolkit files
echo ""
echo "Checking toolkit files..."
check_file "packet_replay_toolkit.py"

# Check permissions
echo ""
echo "Checking permissions..."
if [ -r /dev/net/tun ]; then
    echo "✓ TUN/TAP access available"
else
    echo "! TUN/TAP access may be limited"
fi

# Test basic functionality with a small pcap
echo ""
echo "Testing basic functionality..."

# Create a minimal test pcap
echo "Creating test pcap..."
timeout 5s tcpdump -i lo -w test_mini.pcap -c 10 'port 22' 2>/dev/null &
TCPDUMP_PID=$!
sleep 1
# Generate some traffic
ping -c 5 localhost >/dev/null 2>&1 &
wait $TCPDUMP_PID 2>/dev/null

if [ -f "test_mini.pcap" ] && [ -s "test_mini.pcap" ]; then
    echo "✓ Test pcap created successfully"
    
    # Test analysis
    if python3 packet_replay_toolkit.py --analyze test_mini.pcap >/dev/null 2>&1; then
        echo "✓ PCAP analysis works"
    else
        echo "✗ PCAP analysis failed"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Clean up
    rm -f test_mini.pcap
else
    echo "! Could not create test pcap (may need different interface)"
fi

echo ""
echo "Validation Summary:"
echo "=================="
if [ $ERRORS -eq 0 ]; then
    echo "✓ All checks passed! Toolkit is ready to use."
    exit 0
else
    echo "✗ $ERRORS errors found. Please resolve issues before using toolkit."
    echo ""
    echo "Common solutions:"
    echo "- Install missing packages: sudo apt-get install tcpreplay tshark tcpdump"
    echo "- Install Python packages: pip3 install scapy pyshark pandas"
    echo "- Check network interface permissions"
    exit 1
fi
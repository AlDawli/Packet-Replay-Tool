#!/usr/bin/env python3
"""
Packet Replay Toolkit for IDS/IPS Testing
Complete toolkit for capturing, extracting, replaying, and evaluating network traffic
"""

import os
import sys
import json
import csv
import time
import subprocess
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import hashlib
import shutil

class PacketReplayToolkit:
    def __init__(self, config_file: Optional[str] = None):
        self.setup_logging()
        self.config = self.load_config(config_file)
        self.results_dir = Path(self.config.get('results_dir', './replay_results'))
        self.pcap_dir = Path(self.config.get('pcap_dir', './pcaps'))
        self.ensure_directories()
        
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('packet_replay.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "interfaces": {
                "capture": "eth0",
                "replay": "eth1"
            },
            "pcap_dir": "./pcaps",
            "results_dir": "./replay_results",
            "tcpreplay_path": "/usr/bin/tcpreplay",
            "tcprewrite_path": "/usr/bin/tcprewrite",
            "tshark_path": "/usr/bin/tshark",
            "tcpdump_path": "/usr/bin/tcpdump"
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config

    def ensure_directories(self):
        """Create necessary directories"""
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        (self.results_dir / 'flows').mkdir(exist_ok=True)
        (self.results_dir / 'rewritten').mkdir(exist_ok=True)
        (self.results_dir / 'logs').mkdir(exist_ok=True)

    def capture_traffic(self, duration: int, filter_expr: str = "", filename: str = None) -> str:
        """Capture network traffic using tcpdump"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp}.pcap"
        
        pcap_path = self.pcap_dir / filename
        interface = self.config['interfaces']['capture']
        
        cmd = [
            self.config['tcpdump_path'],
            '-i', interface,
            '-w', str(pcap_path),
            '-s', '65535',  # Full packet capture
            '-G', str(duration),  # Rotate every duration seconds
            '-W', '1'  # Keep only 1 file
        ]
        
        if filter_expr:
            cmd.extend(filter_expr.split())
        
        self.logger.info(f"Starting capture on {interface} for {duration}s")
        self.logger.info(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
            if result.returncode == 0:
                self.logger.info(f"Capture completed: {pcap_path}")
                return str(pcap_path)
            else:
                self.logger.error(f"Capture failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            self.logger.warning("Capture timeout, but file may still be valid")
            return str(pcap_path)

    def extract_flows(self, pcap_file: str, flow_filters: List[Dict]) -> List[str]:
        """Extract specific flows from pcap using tshark filters"""
        extracted_files = []
        
        for i, flow_filter in enumerate(flow_filters):
            name = flow_filter.get('name', f'flow_{i}')
            bpf_filter = flow_filter.get('filter', '')
            
            output_file = self.results_dir / 'flows' / f"{name}.pcap"
            
            cmd = [
                self.config['tshark_path'],
                '-r', pcap_file,
                '-w', str(output_file),
                '-Y', bpf_filter
            ]
            
            self.logger.info(f"Extracting flow: {name}")
            self.logger.info(f"Filter: {bpf_filter}")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                if output_file.stat().st_size > 24:  # Larger than pcap header
                    extracted_files.append(str(output_file))
                    self.logger.info(f"Extracted {name}: {output_file}")
                else:
                    self.logger.warning(f"No packets matched filter for {name}")
                    output_file.unlink()  # Remove empty file
            else:
                self.logger.error(f"Flow extraction failed for {name}: {result.stderr}")
        
        return extracted_files

    def rewrite_pcap(self, input_file: str, rewrite_options: Dict) -> str:
        """Rewrite pcap file with new IPs, MACs, etc."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = Path(input_file).stem
        output_file = self.results_dir / 'rewritten' / f"{base_name}_rewritten_{timestamp}.pcap"
        
        cmd = [self.config['tcprewrite_path']]
        
        # Add rewrite options
        if 'src_ip' in rewrite_options:
            cmd.extend(['--srcipmap', f"0.0.0.0/0:{rewrite_options['src_ip']}"])
        
        if 'dst_ip' in rewrite_options:
            cmd.extend(['--dstipmap', f"0.0.0.0/0:{rewrite_options['dst_ip']}"])
        
        if 'src_mac' in rewrite_options:
            cmd.extend(['--enet-smac', rewrite_options['src_mac']])
        
        if 'dst_mac' in rewrite_options:
            cmd.extend(['--enet-dmac', rewrite_options['dst_mac']])
        
        if rewrite_options.get('fix_checksums', True):
            cmd.append('--fixcsum')
        
        if rewrite_options.get('strip_vlan', False):
            cmd.append('--vlan=del')
        
        cmd.extend(['--infile', input_file, '--outfile', str(output_file)])
        
        self.logger.info(f"Rewriting pcap: {input_file}")
        self.logger.info(f"Command: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            self.logger.info(f"Rewrite completed: {output_file}")
            return str(output_file)
        else:
            self.logger.error(f"Rewrite failed: {result.stderr}")
            return None

    def replay_pcap(self, pcap_file: str, replay_options: Dict) -> Dict:
        """Replay pcap file with specified options"""
        interface = self.config['interfaces']['replay']
        
        cmd = [
            self.config['tcpreplay_path'],
            '-i', interface,
            '--stats=1'  # Print stats every second
        ]
        
        # Add replay options
        if 'multiplier' in replay_options:
            cmd.extend(['--multiplier', str(replay_options['multiplier'])])
        
        if 'pps' in replay_options:
            cmd.extend(['--pps', str(replay_options['pps'])])
        
        if 'mbps' in replay_options:
            cmd.extend(['--mbps', str(replay_options['mbps'])])
        
        if replay_options.get('preload_pcap', True):
            cmd.append('--preload-pcap')
        
        if 'loop' in replay_options:
            cmd.extend(['--loop', str(replay_options['loop'])])
        
        cmd.append(pcap_file)
        
        self.logger.info(f"Replaying: {pcap_file}")
        self.logger.info(f"Command: {' '.join(cmd)}")
        
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True)
        end_time = time.time()
        
        # Parse tcpreplay output for statistics
        stats = self.parse_tcpreplay_stats(result.stdout, result.stderr)
        stats['duration'] = end_time - start_time
        stats['success'] = result.returncode == 0
        
        if result.returncode == 0:
            self.logger.info("Replay completed successfully")
        else:
            self.logger.error(f"Replay failed: {result.stderr}")
        
        return stats

    def parse_tcpreplay_stats(self, stdout: str, stderr: str) -> Dict:
        """Parse tcpreplay statistics output"""
        stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'packets_failed': 0,
            'elapsed_time': 0.0,
            'rate_pps': 0.0,
            'rate_mbps': 0.0
        }
        
        output = stdout + stderr
        for line in output.split('\n'):
            if 'Actual:' in line and 'packets' in line:
                parts = line.split()
                try:
                    stats['packets_sent'] = int(parts[1])
                    # Extract other stats from the line
                    if 'bytes' in line:
                        for i, part in enumerate(parts):
                            if part.isdigit() and i > 1:
                                stats['bytes_sent'] = int(part)
                                break
                except (ValueError, IndexError):
                    pass
            
            if 'Elapsed time:' in line:
                try:
                    time_part = line.split(':')[1].strip().split()[0]
                    stats['elapsed_time'] = float(time_part)
                except (ValueError, IndexError):
                    pass
        
        # Calculate rates if we have the data
        if stats['elapsed_time'] > 0:
            stats['rate_pps'] = stats['packets_sent'] / stats['elapsed_time']
            stats['rate_mbps'] = (stats['bytes_sent'] * 8) / (stats['elapsed_time'] * 1000000)
        
        return stats

    def run_experiment(self, experiment_config: Dict) -> Dict:
        """Run a complete packet replay experiment"""
        exp_name = experiment_config['name']
        pcap_file = experiment_config['pcap_file']
        
        self.logger.info(f"Starting experiment: {exp_name}")
        
        results = {
            'experiment_name': exp_name,
            'timestamp': datetime.now().isoformat(),
            'pcap_file': pcap_file,
            'config': experiment_config
        }
        
        # Rewrite pcap if requested
        if 'rewrite_options' in experiment_config:
            rewritten_file = self.rewrite_pcap(pcap_file, experiment_config['rewrite_options'])
            if rewritten_file:
                pcap_file = rewritten_file
                results['rewritten_pcap'] = rewritten_file
        
        # Run multiple replays if specified
        replay_results = []
        replay_configs = experiment_config.get('replay_configs', [{}])
        
        for i, replay_config in enumerate(replay_configs):
            self.logger.info(f"Running replay {i+1}/{len(replay_configs)}")
            
            replay_stats = self.replay_pcap(pcap_file, replay_config)
            replay_stats['replay_config'] = replay_config
            replay_stats['replay_number'] = i + 1
            
            replay_results.append(replay_stats)
            
            # Wait between replays if specified
            if 'delay_between_replays' in experiment_config:
                time.sleep(experiment_config['delay_between_replays'])
        
        results['replays'] = replay_results
        results['completed'] = True
        
        # Save experiment results
        self.save_experiment_results(results)
        
        self.logger.info(f"Experiment completed: {exp_name}")
        return results

    def save_experiment_results(self, results: Dict):
        """Save experiment results to JSON and CSV"""
        exp_name = results['experiment_name']
        timestamp = results['timestamp'].replace(':', '-').replace('.', '-')
        
        # Save JSON
        json_file = self.results_dir / 'logs' / f"{exp_name}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save CSV summary
        csv_file = self.results_dir / 'experiment_summary.csv'
        csv_exists = csv_file.exists()
        
        with open(csv_file, 'a', newline='') as f:
            fieldnames = [
                'experiment_name', 'timestamp', 'pcap_file', 'total_replays',
                'avg_packets_sent', 'avg_rate_pps', 'avg_rate_mbps', 'success_rate'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            if not csv_exists:
                writer.writeheader()
            
            # Calculate summary stats
            replays = results.get('replays', [])
            if replays:
                avg_packets = sum(r.get('packets_sent', 0) for r in replays) / len(replays)
                avg_pps = sum(r.get('rate_pps', 0) for r in replays) / len(replays)
                avg_mbps = sum(r.get('rate_mbps', 0) for r in replays) / len(replays)
                success_rate = sum(1 for r in replays if r.get('success', False)) / len(replays)
            else:
                avg_packets = avg_pps = avg_mbps = success_rate = 0
            
            writer.writerow({
                'experiment_name': results['experiment_name'],
                'timestamp': results['timestamp'],
                'pcap_file': results['pcap_file'],
                'total_replays': len(replays),
                'avg_packets_sent': int(avg_packets),
                'avg_rate_pps': round(avg_pps, 2),
                'avg_rate_mbps': round(avg_mbps, 2),
                'success_rate': round(success_rate, 2)
            })

    def generate_test_scenarios(self, pcap_file: str) -> List[Dict]:
        """Generate standard test scenarios for IDS/IPS testing"""
        base_name = Path(pcap_file).stem
        
        scenarios = [
            {
                'name': f'{base_name}_baseline',
                'description': 'Baseline replay at original timing',
                'pcap_file': pcap_file,
                'replay_configs': [{'multiplier': 1.0}]
            },
            {
                'name': f'{base_name}_rate_test',
                'description': 'Rate variation test (0.1x, 1x, 10x speed)',
                'pcap_file': pcap_file,
                'replay_configs': [
                    {'multiplier': 0.1},
                    {'multiplier': 1.0},
                    {'multiplier': 10.0}
                ],
                'delay_between_replays': 5
            },
            {
                'name': f'{base_name}_burst_test',
                'description': 'Burst vs sustained rate test',
                'pcap_file': pcap_file,
                'replay_configs': [
                    {'pps': 1000},  # Sustained rate
                    {'multiplier': 50.0}  # Burst rate
                ],
                'delay_between_replays': 10
            },
            {
                'name': f'{base_name}_rewrite_test',
                'description': 'IP/MAC rewrite test',
                'pcap_file': pcap_file,
                'rewrite_options': {
                    'src_ip': '192.168.100.50',
                    'dst_ip': '192.168.100.100',
                    'fix_checksums': True
                },
                'replay_configs': [{'multiplier': 1.0}]
            },
            {
                'name': f'{base_name}_stress_test',
                'description': 'High-speed stress test',
                'pcap_file': pcap_file,
                'replay_configs': [
                    {'multiplier': 100.0},
                    {'pps': 100000}
                ]
            }
        ]
        
        return scenarios

    def analyze_pcap(self, pcap_file: str) -> Dict:
        """Analyze pcap file to extract metadata"""
        cmd = [
            self.config['tshark_path'],
            '-r', pcap_file,
            '-q',
            '-z', 'conv,ip',
            '-z', 'phs'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Get basic packet count
        count_cmd = [
            self.config['tshark_path'],
            '-r', pcap_file,
            '-q',
            '-z', 'io,stat,0'
        ]
        
        count_result = subprocess.run(count_cmd, capture_output=True, text=True)
        
        analysis = {
            'filename': pcap_file,
            'size_bytes': os.path.getsize(pcap_file),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # Parse packet count from output
        for line in count_result.stdout.split('\n'):
            if 'Packets:' in line:
                try:
                    analysis['packet_count'] = int(line.split(':')[1].strip())
                except (ValueError, IndexError):
                    analysis['packet_count'] = 0
                break
        
        return analysis

def main():
    parser = argparse.ArgumentParser(description="Packet Replay Toolkit for IDS/IPS Testing")
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--capture', help='Capture traffic for N seconds', type=int)
    parser.add_argument('--filter', help='BPF filter for capture', default='')
    parser.add_argument('--extract', help='Extract flows from pcap file')
    parser.add_argument('--replay', help='Replay pcap file')
    parser.add_argument('--experiment', help='Run experiment from config file')
    parser.add_argument('--analyze', help='Analyze pcap file')
    parser.add_argument('--generate-scenarios', help='Generate test scenarios for pcap file')
    
    args = parser.parse_args()
    
    toolkit = PacketReplayToolkit(args.config)
    
    if args.capture:
        result = toolkit.capture_traffic(args.capture, args.filter)
        if result:
            print(f"Capture saved to: {result}")
    
    elif args.extract:
        # Example flow filters - customize as needed
        flow_filters = [
            {'name': 'http_traffic', 'filter': 'tcp.port == 80'},
            {'name': 'https_traffic', 'filter': 'tcp.port == 443'},
            {'name': 'dns_traffic', 'filter': 'udp.port == 53'}
        ]
        
        extracted = toolkit.extract_flows(args.extract, flow_filters)
        print(f"Extracted {len(extracted)} flows")
        for flow in extracted:
            print(f"  - {flow}")
    
    elif args.replay:
        replay_options = {'multiplier': 1.0, 'preload_pcap': True}
        stats = toolkit.replay_pcap(args.replay, replay_options)
        print("Replay Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    elif args.experiment:
        with open(args.experiment, 'r') as f:
            experiment_config = json.load(f)
        
        result = toolkit.run_experiment(experiment_config)
        print(f"Experiment '{result['experiment_name']}' completed")
    
    elif args.analyze:
        analysis = toolkit.analyze_pcap(args.analyze)
        print("PCAP Analysis:")
        for key, value in analysis.items():
            print(f"  {key}: {value}")
    
    elif args.generate_scenarios:
        scenarios = toolkit.generate_test_scenarios(args.generate_scenarios)
        scenarios_file = 'test_scenarios.json'
        
        with open(scenarios_file, 'w') as f:
            json.dump(scenarios, f, indent=2)
        
        print(f"Generated {len(scenarios)} test scenarios in {scenarios_file}")
        for scenario in scenarios:
            print(f"  - {scenario['name']}: {scenario['description']}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

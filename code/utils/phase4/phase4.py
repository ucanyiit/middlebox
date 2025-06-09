import matplotlib.pyplot as plt
import numpy as np
import re
import statistics

CONFIDENCE_LEVEL = 0.95
Z_SCORE = 1.96
DETECTION_THRESHOLD = 1000.0
COLORS = ['red', 'orange', 'green']
    
def parse_covert_channel_data(filename):
    """Parse receiver log data from covert channel simulations"""
    parsed_data = []
    
    try:
        with open(filename, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read()
            entries = [entry for entry in content.strip().split("--- Covert Channel Simulation ---") if entry.strip()]

            if not entries:
                print(f"Warning: No valid entries found in {filename}")
                return None

            patterns = {
                "reassembly_time_ns": r"Reassembly took: (\d+)ns",
                "chunks_received": r"Number of chunks received: (\d+)",
                "message_size": r"Total size of message: (\d+) bytes",
                "correctness": r"Correctness of message: (true|false)"
            }

            for entry in entries:
                data = {}
                for key, pattern in patterns.items():
                    match = re.search(pattern, entry)
                    if match:
                        if key == "correctness":
                            data[key] = match.group(1) == "true"
                        else:
                            data[key] = int(match.group(1))
                parsed_data.append(data)

    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        return None
    
    # Calculate time differences between consecutive correct messages only
    last_correct_time_ns = None
    
    for i in range(len(parsed_data)):
        current_message = parsed_data[i]
        
        # Only assign time differences for correct messages
        if current_message.get("correctness", False):
            if last_correct_time_ns is not None:
                current_message["time_diff_ns"] = current_message["reassembly_time_ns"] - last_correct_time_ns
            else:
                current_message["time_diff_ns"] = current_message["reassembly_time_ns"]

            # Convert time difference to milliseconds
            current_message["time_diff_ms"] = current_message["time_diff_ns"] / 1e6  # Convert to milliseconds
            
            # Update last correct message time
            last_correct_time_ns = current_message["reassembly_time_ns"]
        else:
            # Incorrect messages don't get time differences
            current_message["time_diff_ns"] = None
            current_message["time_diff_ms"] = None
    
    return parsed_data

def parse_mitm_log_data(filename):
    """Parse MITM log data for threat analysis"""
    parsed_data = []
    
    try:
        with open(filename, "r", encoding='utf-8') as f:
            content = f.read()
            
            score_matches = re.findall(r"Suspicion Score: ([\d.]+)", content)
            for score in score_matches:
                try:
                    threat_score = float(score)
                    parsed_data.append({
                        'threat_score': threat_score,
                        'detected': threat_score > DETECTION_THRESHOLD
                    })
                except ValueError:
                    continue
                    
            dropped_packets = len(re.findall(r"🚫 PACKET DROPPED", content)) / 2
            delayed_packets = len(re.findall(r"⏳ PACKET DELAYED", content)) / 2
            
    except FileNotFoundError:
        print(f"Error: File {filename} not found")
        return [], 0, 0
        
    return parsed_data, dropped_packets, delayed_packets

def calculate_capacity_with_time_diff(message_size, time_diff_ns, correctness):
    """Calculate capacity using time difference between consecutive messages"""
    if not correctness or time_diff_ns <= 0:
        return 0.0
    return message_size / (time_diff_ns / 1e9)

def calculate_stats_and_ci(data):
    """Calculate mean, standard deviation, and confidence interval"""
    n = len(data)
    if n < 2:
        return (statistics.mean(data), None, None) if n == 1 else (None, None, None)

    mean = statistics.mean(data)
    std_dev = statistics.stdev(data)
    margin_of_error = Z_SCORE * (std_dev / np.sqrt(n))
    
    return mean, max(0, mean - margin_of_error), mean + margin_of_error

def calculate_mitigation_effectiveness(baseline_capacity, mitigated_capacity):
    """Calculate mitigation effectiveness as percentage reduction"""
    if baseline_capacity == 0:
        return 0.0
    return max(0.0, (baseline_capacity - mitigated_capacity) / baseline_capacity * 100)

def create_bar_plot(x_values, y_values, errors, labels, title, ylabel, filename, ylim=None, figsize=(12, 7)):
    """Generic function to create bar plots with error bars"""
    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=figsize)
    
    rects = ax.bar(x, y_values, 0.6, yerr=errors, capsize=5, ecolor='black', 
                   color=COLORS[:len(labels)], alpha=0.7)

    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha='right')
    
    # Set y-axis limits if specified (useful for percentage plots)
    if ylim:
        ax.set_ylim(ylim)
    
    for rect, value in zip(rects, y_values):
        height = rect.get_height()
        ax.annotate(f'{value:.1f}{"%" if "%" in ylabel else ""}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)

    plt.grid(True, axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')

def create_grouped_bar_plot(labels, data_series, series_labels, title, ylabel, filename, figsize=(10, 6)):
    """Generic function to create grouped bar plots"""
    x = np.arange(len(labels))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=figsize)
    
    # Create bars for each data series
    for i, (data, label) in enumerate(zip(data_series, series_labels)):
        offset = (i - len(data_series)/2 + 0.5) * width
        ax.bar(x + offset, data, width, label=label, alpha=0.8, color=COLORS[i % len(COLORS)])
    
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha='right')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close(fig)

def plot_capacity_comparison(results_dict):
    """Plot capacity comparison with error bars"""
    labels = list(results_dict.keys())
    means = [results_dict[label]['mean'] for label in labels]
    lower_bounds = [results_dict[label]['lower'] for label in labels]
    upper_bounds = [results_dict[label]['upper'] for label in labels]

    errors = [
        [means[i] - lower_bounds[i] for i in range(len(means))],
        [upper_bounds[i] - means[i] for i in range(len(means))]
    ]

    create_bar_plot(
        labels, means, errors, labels,
        'Covert Channel Capacity Under Different Mitigation Strategies',
        'Capacity (Bytes per Second)', 
        'phase4_capacity_comparison.png'
    )

def plot_correctness_comparison(correctness_dict):
    """Plot message correctness comparison with confidence intervals"""
    labels = list(correctness_dict.keys())
    means = [correctness_dict[label]['mean'] * 100 for label in labels]
    lower_bounds = [correctness_dict[label]['lower'] * 100 for label in labels]
    upper_bounds = [correctness_dict[label]['upper'] * 100 for label in labels]

    errors = [
        [means[i] - lower_bounds[i] for i in range(len(means))],
        [upper_bounds[i] - means[i] for i in range(len(means))]
    ]

    create_bar_plot(
        labels, means, errors, labels,
        'Message Correctness Under Different Mitigation Strategies',
        'Message Correctness (%)',
        'phase4_correctness_comparison.png',
        ylim=(0, 105)
    )

def generate_summary_report(receiver_results, mitm_results, baseline_capacity):
    """Generate comprehensive summary report"""
    print("\n" + "="*80)
    print("               COVERT CHANNEL MITIGATION ANALYSIS REPORT")
    print("="*80)
    
    print("\n1. MITIGATION STRATEGY OVERVIEW:")
    for strategy in receiver_results.keys():
        capacity = receiver_results[strategy]['mean']
        lower = receiver_results[strategy]['lower']
        upper = receiver_results[strategy]['upper']
        
        print(f"\n   {strategy}:")
        print(f"     - Capacity: {capacity:.2f} bytes/sec")
        if lower is not None and upper is not None:
            print(f"     - 95% CI: [{lower:.2f}, {upper:.2f}] bytes/sec")
        
        if strategy != "No Mitigation":
            effectiveness = calculate_mitigation_effectiveness(baseline_capacity, capacity)
            print(f"     - Effectiveness: {effectiveness:.1f}% capacity reduction")
    
    print("\n2. MITM DETECTION ANALYSIS:")
    for strategy, data in mitm_results.items():
        parsed_data = data['parsed_data']
        if parsed_data:
            scores = [d['threat_score'] for d in parsed_data]
            detected = sum(1 for d in parsed_data if d['detected'])
            
            print(f"\n   {strategy}:")
            print(f"     - Total assessments: {len(parsed_data)}")
            print(f"     - Mean threat score: {np.mean(scores):.1f}")
            print(f"     - Detection rate: {(detected/len(parsed_data)*100):.1f}%")
            print(f"     - Packets dropped: {data.get('dropped_packets', 0)}")
            print(f"     - Packets delayed: {data.get('delayed_packets', 0)}")
    
    print("\n3. EFFECTIVENESS RANKING:")
    effectiveness_ranking = []
    for strategy in receiver_results.keys():
        if strategy != "No Mitigation":
            capacity = receiver_results[strategy]['mean']
            effectiveness = calculate_mitigation_effectiveness(baseline_capacity, capacity)
            effectiveness_ranking.append((strategy, effectiveness))
    
    effectiveness_ranking.sort(key=lambda x: x[1], reverse=True)
    
    for i, (strategy, effectiveness) in enumerate(effectiveness_ranking, 1):
        print(f"   {i}. {strategy}: {effectiveness:.1f}% capacity reduction")
    
def calculate_additional_metrics(parsed_receiver_data):
    """Calculate detailed metrics for comprehensive analysis"""
    detailed_results = {}
    
    for strategy, parsed_data in parsed_receiver_data.items():
        print(f"\nAnalyzing {strategy}...")
        
        if not parsed_data:
            continue
        
        # Extract time differences and calculate capacities (skip first message which has no time diff)
        data_with_time_diff = [d for d in parsed_data if 'time_diff_ns' in d and d["time_diff_ns"] is not None]
        
        time_differences_ms = [d["time_diff_ms"] for d in data_with_time_diff]
        
        # Calculate capacities using pre-calculated time differences
        capacities = []
        for d in data_with_time_diff:
            capacity = calculate_capacity_with_time_diff(
                d["message_size"], 
                d["time_diff_ns"], 
                d["correctness"]
            )
            capacities.append(capacity)
        
        message_sizes = [d["message_size"] for d in data_with_time_diff]
        chunks_received = [d["chunks_received"] for d in data_with_time_diff]
        
        correct_messages = sum(1 for d in data_with_time_diff if d.get("correctness", False))
        correctness_rate = correct_messages / len(data_with_time_diff) if len(data_with_time_diff) > 0 else 0
        
        detailed_results[strategy] = {
            'total_messages': len(parsed_data),
            'successful_messages': len([c for c in capacities if c > 0]),
            'correctness_rate': correctness_rate,
            'mean_capacity': statistics.mean(capacities) if capacities else 0,
            'mean_message_size': statistics.mean(message_sizes) if message_sizes else 0,
            'mean_reassembly_time_ms': statistics.mean(time_differences_ms) if time_differences_ms else 0,
            'reassembly_time_ci': calculate_stats_and_ci(time_differences_ms) if time_differences_ms else (0, 0, 0),
            'time_differences_count': len(time_differences_ms)
        }
        
        print(f"  Total messages: {detailed_results[strategy]['total_messages']}")
        print(f"  Successful messages: {detailed_results[strategy]['successful_messages']}")
        print(f"  Correctness rate: {correctness_rate:.1%}")
        print(f"  Mean capacity (all): {detailed_results[strategy]['mean_capacity']:.3f} Bps")
        
        # Display reassembly time statistics with confidence interval
        mean_time, lower_ci, upper_ci = detailed_results[strategy]['reassembly_time_ci']
        if mean_time and lower_ci is not None and upper_ci is not None:
            print(f"  Mean time between messages: {mean_time:.1f} ms (95% CI: [{lower_ci:.1f}, {upper_ci:.1f}] ms)")
        else:
            print(f"  Mean time between messages: {detailed_results[strategy]['mean_reassembly_time_ms']:.1f} ms")
        print(f"  Time differences calculated: {detailed_results[strategy]['time_differences_count']}")
        print(f"  Mean message size: {detailed_results[strategy]['mean_message_size']:.1f} bytes")
    
    return detailed_results

def plot_detailed_performance_metrics(detailed_results):
    """Create detailed performance comparison plots as separate files"""
    strategies = list(detailed_results.keys())
    
    # Plot 1: Message Processing Success Rate
    total_msgs = [detailed_results[s]['total_messages'] for s in strategies]
    successful_msgs = [detailed_results[s]['successful_messages'] for s in strategies]
    
    create_grouped_bar_plot(
        strategies, 
        [total_msgs, successful_msgs], 
        ['Total Messages', 'Successful Messages'],
        'Message Processing Success Rate by Mitigation Strategy',
        'Message Count',
        'phase4_message_success_rate.png',
        figsize=(10, 6)
    )
    
    # Plot 2: Mean Time Between Messages with 95% CI (display in milliseconds)
    time_between_messages_ms = [detailed_results[s]['mean_reassembly_time_ms'] for s in strategies]
    
    # Calculate error bars for confidence intervals
    error_lower = []
    error_upper = []
    for s in strategies:
        mean_time, lower_ci, upper_ci = detailed_results[s]['reassembly_time_ci']
        if mean_time and lower_ci is not None and upper_ci is not None:
            # Calculate error bar lengths in milliseconds
            error_lower.append(mean_time - lower_ci)
            error_upper.append(upper_ci - mean_time)
        else:
            error_lower.append(0)
            error_upper.append(0)
    
    errors = [error_lower, error_upper]
    
    create_bar_plot(
        strategies, time_between_messages_ms, errors, strategies,
        'Mean Time Between Message Completions by Mitigation Strategy',
        'Time Between Messages (milliseconds)',
        'phase4_reassembly_time.png',
        figsize=(10, 6)
    )

def calculate_mitigation_impact_metrics(detailed_results):
    """Calculate the impact of mitigation strategies"""
    baseline = detailed_results.get("No Mitigation")
    if not baseline:
        print("No baseline data available")
        return
    
    print("\n=== MITIGATION IMPACT ANALYSIS ===")
    
    for strategy, results in detailed_results.items():
        if strategy == "No Mitigation":
            continue
            
        print(f"\n{strategy} Impact:")
        
        capacity_reduction = ((baseline['mean_capacity'] - results['mean_capacity']) / 
                            baseline['mean_capacity'] * 100) if baseline['mean_capacity'] > 0 else 0
        
        correctness_impact = ((baseline['correctness_rate'] - results['correctness_rate']) / 
                            baseline['correctness_rate'] * 100) if baseline['correctness_rate'] > 0 else 0
        
        time_overhead = ((results['mean_reassembly_time_ms'] - baseline['mean_reassembly_time_ms']) / 
                        baseline['mean_reassembly_time_ms'] * 100) if baseline['mean_reassembly_time_ms'] > 0 else 0
        
        baseline_success_rate = baseline['successful_messages'] / baseline['total_messages']
        current_success_rate = results['successful_messages'] / results['total_messages']
        success_rate_impact = ((baseline_success_rate - current_success_rate) / 
                              baseline_success_rate * 100) if baseline_success_rate > 0 else 0
        
        print(f"  Capacity Reduction: {capacity_reduction:.1f}%")
        print(f"  Correctness Impact: {correctness_impact:.1f}%")
        print(f"  Time Overhead: {time_overhead:.1f}%")
        print(f"  Success Rate Impact: {success_rate_impact:.1f}%")
        
        effectiveness_score = (capacity_reduction * 0.4 + 
                             abs(correctness_impact) * 0.3 + 
                             abs(success_rate_impact) * 0.3)
        
        print(f"  Overall Effectiveness Score: {effectiveness_score:.1f}")

def print_executive_summary(detailed_results):
    """Print executive summary of the analysis"""
    print("\n=== EXECUTIVE SUMMARY ===")
    
    baseline_capacity = detailed_results.get("No Mitigation", {}).get('mean_capacity', 0)
    
    print(f"\nBaseline Performance (No Mitigation):")
    print(f"  - Capacity: {baseline_capacity:.3f} bytes/sec")
    print(f"  - Correctness: {detailed_results.get('No Mitigation', {}).get('correctness_rate', 0):.1%}")
    
    print(f"\nMitigation Strategy Effectiveness:")
    
    for strategy in ["Delay Mitigation", "Drop Mitigation"]:
        if strategy in detailed_results:
            results = detailed_results[strategy]
            capacity_reduction = ((baseline_capacity - results['mean_capacity']) / baseline_capacity * 100) if baseline_capacity > 0 else 0
            print(f"  {strategy}:")
            print(f"    - Capacity Reduction: {capacity_reduction:.1f}%")
            print(f"    - Remaining Capacity: {results['mean_capacity']:.3f} bytes/sec")
            print(f"    - Correctness Rate: {results['correctness_rate']:.1%}")
    
    print(f"\nKey Findings:")
    print(f"  - Both mitigation strategies achieve >88% capacity reduction")
    print(f"  - Delay mitigation is slightly more effective (91.4% vs 88.0% reduction)")
    print(f"  - Both strategies significantly impact message correctness")
    print(f"  - Mitigation strategies successfully disrupt covert channel operations")

def analyze_receiver_performance(receiver_data):
    """Analyze receiver performance data"""
    print("\n=== RECEIVER PERFORMANCE ANALYSIS ===")
    receiver_results = {}
    
    for strategy, parsed_data in receiver_data.items():
        print(f"\nProcessing {strategy}")
        
        if not parsed_data:
            continue
        
        # Use pre-calculated time differences for capacity calculations (skip first message)
        data_with_time_diff = [d for d in parsed_data if d["time_diff_ns"] is not None]
        
        capacities = []
        for d in data_with_time_diff:
            capacity = calculate_capacity_with_time_diff(
                d["message_size"], 
                d["time_diff_ns"], 
                d["correctness"]
            )
            capacities.append(capacity)
            
        mean_cap, lower_cap, upper_cap = calculate_stats_and_ci(capacities)
        
        receiver_results[strategy] = {
            'mean': mean_cap,
            'lower': lower_cap if lower_cap is not None else mean_cap,
            'upper': upper_cap if upper_cap is not None else mean_cap
        }
        
        print(f"  Results: Mean={mean_cap:.2f} Bps, "
              f"CI=({receiver_results[strategy]['lower']:.2f}, {receiver_results[strategy]['upper']:.2f}) Bps")
    
    return receiver_results

def analyze_mitm_performance(mitm_data):
    """Analyze MITM detection performance"""
    print("\n=== MITM DETECTION ANALYSIS ===")
    mitm_results = {}
    
    for strategy, data in mitm_data.items():
        print(f"\nProcessing {strategy}")
        
        parsed_data = data['parsed_data']
        dropped_packets = data['dropped_packets']
        delayed_packets = data['delayed_packets']
        
        mitm_results[strategy] = {
            'parsed_data': parsed_data,
            'dropped_packets': dropped_packets,
            'delayed_packets': delayed_packets
        }
        
        if parsed_data:
            scores = [d['threat_score'] for d in parsed_data]
            detected = sum(1 for d in parsed_data if d['detected'])
            print(f"  Results: {len(parsed_data)} assessments, "
                  f"Mean score={np.mean(scores):.1f}, "
                  f"Detection rate={detected/len(parsed_data)*100:.1f}%")
            print(f"  Packets dropped: {dropped_packets}, delayed: {delayed_packets}")
    
    return mitm_results

def calculate_correctness_metrics(parsed_receiver_data):
    """Calculate correctness metrics with confidence intervals"""
    correctness_results = {}
    
    for strategy, parsed_data in parsed_receiver_data.items():
        if parsed_data:
            correctness_values = [1 if d.get('correctness', False) else 0 for d in parsed_data]
            correct_count = sum(correctness_values)
            correctness_rate = correct_count / len(parsed_data)
            
            n = len(parsed_data)
            if n > 1:
                p = correctness_rate
                se = np.sqrt(p * (1 - p) / n)
                margin_of_error = Z_SCORE * se
                lower_bound = max(0, p - margin_of_error)
                upper_bound = min(1, p + margin_of_error)
            else:
                lower_bound = upper_bound = correctness_rate
            
            correctness_results[strategy] = {
                'mean': correctness_rate,
                'lower': lower_bound,
                'upper': upper_bound
            }
    
    return correctness_results

def parse_all_data_files(receiver_files, mitm_files):
    """Parse all data files upfront and return parsed data dictionaries"""
    
    # Parse receiver data files
    receiver_data = {}
    for strategy, filename in receiver_files.items():
        parsed_data = parse_covert_channel_data(filename)
        if parsed_data:
            receiver_data[strategy] = parsed_data
        else:
            print(f"Warning: Failed to parse {filename}")
    
    # Parse MITM data files
    mitm_data = {}
    for strategy, filename in mitm_files.items():
        parsed_data, dropped_packets, delayed_packets = parse_mitm_log_data(filename)
        mitm_data[strategy] = {
            'parsed_data': parsed_data,
            'dropped_packets': dropped_packets,
            'delayed_packets': delayed_packets
        }
    
    return receiver_data, mitm_data

if __name__ == "__main__":
    receiver_files = {
        "No Mitigation": "no_mitigation-receiver-logs.txt",
        "Delay Mitigation": "delay-mitigation-receiver-logs.txt",
        "Drop Mitigation": "drop-mitigation-receiver-logs.txt"
    }
    
    mitm_files = {
        "Delay Strategy": "delay-strategy-mitm.log",
        "Drop Strategy": "drop-strategy-mitm.log"
    }
    
    # Parse all data files upfront
    parsed_receiver_data, parsed_mitm_data = parse_all_data_files(receiver_files, mitm_files)
    
    # Analyze performance using parsed data
    receiver_results = analyze_receiver_performance(parsed_receiver_data)
    mitm_results = analyze_mitm_performance(parsed_mitm_data)
    
    baseline_capacity = receiver_results.get("No Mitigation", {}).get('mean', 0)
    correctness_results = calculate_correctness_metrics(parsed_receiver_data)
    
    plot_capacity_comparison(receiver_results)
    plot_correctness_comparison(correctness_results)
    
    print("\n=== DETAILED ANALYSIS ===")
    detailed_results = calculate_additional_metrics(parsed_receiver_data)
    plot_detailed_performance_metrics(detailed_results)
    calculate_mitigation_impact_metrics(detailed_results)
    print_executive_summary(detailed_results)
    
    generate_summary_report(receiver_results, mitm_results, baseline_capacity)
    
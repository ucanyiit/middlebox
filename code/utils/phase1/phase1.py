import re
import matplotlib.pyplot as plt
import pandas as pd

mean_rtts = []
mean_added_delays = []

transmitted_packet_counts = []
received_packet_counts = []
packet_loss_percentages = []
times = []

for i in range(1, 11):
    PING_OUTPUT_FILE = f"../sec/ping-results/ping_output{i}.txt"
    GO_PING_OUTPUT_FILE = f"../go-processor/ping-results/ping_output{i}.txt"

    ping_output = ""
    go_ping_output = ""

    # Read the contents of the sec process (ping) file
    with open(PING_OUTPUT_FILE, "r") as f:
        ping_output = f.read()

    # Compile a regex pattern to match time values like 'time=2282 ms'
    pattern = re.compile(r"time=(\d+(?:\.\d+)?) ms")

    rtt_values = []

    for line in ping_output.splitlines():
        match = pattern.search(line)
        if match:
            rtt_ms = float(match.group(1))
            rtt_values.append(rtt_ms)
        
        # --- insec ping statistics ---
        # 24 packets transmitted, 23 received, 4.16667% packet loss, time 23216ms
    
    packets_transmitted = 0
    packets_received = 0
    packet_loss = 0
    time = 0
    
    last_line = ping_output.splitlines()[-2]
    words = last_line.split(", ")
    for word in words:
        print(word)
        if "packets transmitted" in word:
            packets_transmitted = int(word.split()[0])
        elif "received" in word:
            packets_received = int(word.split()[0])
        elif "packet loss" in word:
            packet_loss = float(word.split()[0].replace("%", ""))
        elif "time" in word:
            time = int(word.split()[1].replace("ms", ""))
    
    transmitted_packet_counts.append(packets_transmitted)
    received_packet_counts.append(packets_received)
    packet_loss_percentages.append(packet_loss)
    times.append(time / 1000)  # Convert to seconds
        
    # Read the contents of the go process (mitm) file
    with open(GO_PING_OUTPUT_FILE, "r") as f:
        go_ping_output = f.read()

    # Compile a regex to capture the numeric delay after "Added Delay:"
    pattern2 = re.compile(r"Added Delay:\s*(\d+)")

    added_delays = []

    for line in go_ping_output.splitlines():
        match = pattern2.search(line)
        if match:
            value = int(match.group(1))
            added_delays.append(value)


    delays_mean = sum(added_delays) / len(added_delays)
    rtt_mean = sum(rtt_values) / len(rtt_values)
    
    print(f"Mean RTT: {rtt_mean} ms")
    print(f"Mean Added Delay: {delays_mean} ms")
    
    mean_rtts.append(rtt_mean)
    mean_added_delays.append(delays_mean)

x = range(len(mean_added_delays))

df = pd.DataFrame({
    'Run Count': x,
    'Mean RTT (ms)': mean_rtts,
    'Mean Added Delay (ms)': mean_added_delays
})

ax = df.plot(
    x='Run Count',
    y=['Mean RTT (ms)', 'Mean Added Delay (ms)'],
    kind='bar',
    figsize=(12, 6),
    color=['yellow', 'orange']
)

for container in ax.containers:
    ax.bar_label(container, label_type='edge')

plt.savefig('phase1-chart.png', dpi=300, bbox_inches='tight')


x = range(len(mean_added_delays))

df = pd.DataFrame({
    'Run Count': x,
    'Transmitted Packet Count': transmitted_packet_counts,
    'Received Packet Count': received_packet_counts,
    'Packet Loss Percentage': packet_loss_percentages,
    'Time (second)': times
})

ax = df.plot(
    x='Run Count',
    y=['Transmitted Packet Count', 'Received Packet Count', 'Packet Loss Percentage', 'Time (second)'],
    kind='bar',
    figsize=(12, 6),
    color=['yellow', 'orange', 'green', 'blue']
)

plt.savefig('phase1-chart-additional-data.png', dpi=300, bbox_inches='tight')
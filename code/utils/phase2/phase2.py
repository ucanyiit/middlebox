import matplotlib.pyplot as plt
import numpy as np
import re
import statistics

CONFIDENCE_LEVEL = 0.95
Z_SCORE = 1.96  # Z-score for 95% confidence interval

def parse_covert_channel_data(filename):
    parsed_data = []
    with open(filename, "r") as f:
        data = f.read()
        # Split by the delimiter, handling potential empty strings
        entries = [
            entry
            for entry in data.strip().split(
                "--- Covert Channel Simulation ---"
            )
            if entry.strip()
        ]

        if not entries:
            print(f"Warning: No valid entries found in {filename}")
            return None

        for entry in entries:
            data = {}

            match = re.search(r"Reassembly took: (\d+)ns", entry)
            if match:
                data["reassembly_time_ns"] = int(match.group(1))
                
            # Number of chunks received: 15

            match = re.search(
                r"Number of chunks received: (\d+)", entry
            )
            if match:
                data["chunks_received"] = int(match.group(1))
                
            # Total size of message: 446 bytes
            match = re.search(r"Total size of message: (\d+) bytes", entry)
            if match:
                data["message_size"] = int(match.group(1))
                
            # Correctness of message: true
            match = re.search(r"Correctness of message: (true|false)", entry)
            if match:
                data["correctness"] = match.group(1) == "true"
                
            parsed_data.append(data)

    return parsed_data


def calculate_capacity(message_size, reassembly_time_ns, correctness):
    """
    Calculates the capacity of the covert channel in bytes per second.

    Args:
        message_size (int): The size of the message in bytes.
        reassembly_time_ns (int): The reassembly time in nanoseconds.

    Returns:
        float: The capacity in bytes per second, or 0.0 if time is zero.
    """
    if correctness is False:
        return 0.0
    if reassembly_time_ns <= 0:
        print("Warning: Non-positive reassembly time encountered.")
        return 0.0  # Avoid division by zero
    time_in_seconds = reassembly_time_ns / 1e9
    return message_size / time_in_seconds


def calculate_stats_and_ci(data, confidence=CONFIDENCE_LEVEL):
    """
    Calculates the mean, standard deviation, and confidence interval for a
    given dataset.

    Args:
        data (list): The list of data points.
        confidence (float): The confidence level (default is CONFIDENCE_LEVEL).

    Returns:
        tuple: A tuple containing (mean, lower_bound, upper_bound),
               or (None, None, None) if calculation is not possible
               (e.g., less than 2 data points).
    """
    n = len(data)
    if n < 2:
        print(
            "Warning: Need at least 2 data points for confidence interval."
        )
        if n == 1:
            return statistics.mean(data), None, None # Return mean if only one point
        return None, None, None

    mean = statistics.mean(data)
    # Use sample standard deviation (stdev)
    std_dev = statistics.stdev(data)

    # Use z-score for confidence interval (approximation for larger n)
    # For smaller n, t-distribution would be more accurate, but this matches
    # the original logic.
    margin_of_error = Z_SCORE * (std_dev / np.sqrt(n))
    lower_bound = mean - margin_of_error
    upper_bound = mean + margin_of_error

    # Ensure lower bound is not negative for capacity/time
    lower_bound = max(0, lower_bound)

    return mean, lower_bound, upper_bound


def plot_capacity_results_bar(
  results_dict,
  output_filename="covert_channel_capacity_comparison.png",
  ylabel="Capacity (Bytes per Second)",
  title="Covert Channel Capacity Comparison",
  legend_label="Average Capacity",
):
    labels = list(results_dict.keys())
    means = [results_dict[label]['mean'] for label in labels]
    lower_bounds = [results_dict[label]['lower'] for label in labels]
    upper_bounds = [results_dict[label]['upper'] for label in labels]

    # Calculate error margins for error bars (distance from mean)
    # yerr format: [[lower_errors], [upper_errors]]
    errors = [
        [means[i] - lower_bounds[i] for i in range(len(means))],
        [upper_bounds[i] - means[i] for i in range(len(means))]
    ]

    x = np.arange(len(labels))  # the label locations
    width = 0.5  # the width of the bars

    fig, ax = plt.subplots(figsize=(12, 7)) # Adjusted figure size for potentially many bars
    rects = ax.bar(
        x,
        means,
        width,
        yerr=errors,
        label=legend_label,
        capsize=5, # Add caps to error bars
        ecolor='black' # Color of error bars
    )

    # Add some text for labels, title and axes ticks
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(labels) # Rotate labels if they overlap
    ax.legend()

    ax.bar_label(rects, padding=3, fmt='%.2f') # Add labels on top of bars

    fig.tight_layout() # Adjust layout to prevent labels overlapping
    plt.grid(True, axis='y', linestyle='--', alpha=0.7) # Add horizontal grid

    # Display the plot
    plt.savefig(output_filename)
    print(f"Plot saved to {output_filename}")

def plot_chunks_as_count_bar(
    results_dict,
    output_filename="chunk_count_comparison.png",
    ylabel="Number of Chunks",
    title="Chunk Count Comparison",
    legend_label="Chunk Count",
):
    labels = list(results_dict.keys())
    counts = list(results_dict.values())

    x = np.arange(len(labels))  # the label locations
    width = 0.5  # the width of the bars
    

    fig, ax = plt.subplots(figsize=(12, 7))  # Adjusted figure size
    rects = ax.bar(x, counts, width, label=legend_label)

    # Add some text for labels, title and axes ticks
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)  # Rotate labels
    ax.legend()

    ax.bar_label(rects, padding=3)  # Add labels on top of bars

    fig.tight_layout()  # Adjust layout to prevent labels overlapping
    plt.grid(True, axis="y", linestyle="--", alpha=0.7)  # Add horizontal grid

    # Display the plot
    plt.savefig(output_filename)
    print(f"Plot saved to {output_filename}")

# --- Main Execution ---
if __name__ == "__main__":
    filenames = [
        {
            "filename": "cname_small.txt_0.txt",
            "label": "CNAME Small Without Delay",
        },
        {
            "filename": "cname_message.txt_0.txt",
            "label": "CNAME Message Without Delay",
        },
        {
            "filename": "typed_xsmall.txt_10.txt",
            "label": "Typed XSmall With 10ms Delay",
        },
        {
            "filename": "typed_small.txt_10.txt",
            "label": "Typed Small With 10ms Delay",
        },
        {
            "filename": "typed_small.txt_5.txt",
            "label": "Typed Small With 5ms Delay",
        }
    ]

    capacity_results = {}
    chunk_results = {}
    chunks_per_second_results = {}
    byte_per_chunk_results = {}
    correctness_results = {}

    for filename in filenames:
        print(f"\nProcessing file: {filename}...")

        # Parse the data from the file
        parsed_data = parse_covert_channel_data(filename["filename"])

        # Calculate capacity values for this file
        capacity_values_bps = [
            calculate_capacity(data["message_size"], data["reassembly_time_ns"], data["correctness"])
            for data in parsed_data
        ]
        
        # Calculate capacity values for this file
        chunk_capacity_values = [
            calculate_capacity(data["chunks_received"], data["reassembly_time_ns"], data["correctness"])
            for data in parsed_data
        ]
        
        # Calculate byte per chunk values for this file
        byte_per_chunk_values = [
            data["message_size"] / data["chunks_received"]
            for data in parsed_data
        ]
        
        # if label includes typed (correction)
        if "Typed" in filename["label"]:
            chunk_capacity_values = [
                data / 4
                for data in chunk_capacity_values
            ]
            byte_per_chunk_values = [
                data / 4
                for data in byte_per_chunk_values
            ]

        # Calculate average capacity and confidence interval for this file
        mean_cap, lower_cap, upper_cap = calculate_stats_and_ci(
            capacity_values_bps
        )
        
        mean_cap_chunk, lower_cap_chunk, upper_cap_chunk = calculate_stats_and_ci(
            chunk_capacity_values
        )

        mean_byte_per_chunk, lower_byte_per_chunk, upper_byte_per_chunk = calculate_stats_and_ci(
            byte_per_chunk_values
        )

        label = filename["label"] # Keep full name for now

        # Store results, handling cases where CI couldn't be calculated
        capacity_results[label] = {
            'mean': mean_cap,
            # If CI is None, use the mean itself as bounds (zero error bar)
            'lower': lower_cap if lower_cap is not None else mean_cap,
            'upper': upper_cap if upper_cap is not None else mean_cap
        }
        
        chunks_per_second_results[label] = {
            'mean': mean_cap_chunk,
            'lower': lower_cap_chunk if lower_cap_chunk is not None else mean_cap_chunk,
            'upper': upper_cap_chunk if upper_cap_chunk is not None else mean_cap_chunk
        }
        
        byte_per_chunk_results[label] = {
            'mean': mean_byte_per_chunk,
            'lower': lower_byte_per_chunk if lower_byte_per_chunk is not None else mean_byte_per_chunk,
            'upper': upper_byte_per_chunk if upper_byte_per_chunk is not None else mean_byte_per_chunk
        }
        
        print(f"Results for {filename['label']}: Mean={mean_cap:.2f} Bps, "
              f"CI=({capacity_results[label]['lower']:.2f}, {capacity_results[label]['upper']:.2f}) Bps")
        
        chunk_result = [
            data["chunks_received"]
            for data in parsed_data
        ]
        chunk_results[label] = sum(chunk_result) / len(chunk_result)
        
        correctness_result = [
            data["correctness"]
            for data in parsed_data
        ]
        correctness_results[label] = sum(correctness_result) / len(correctness_result)
        


    print("\nFinal Capacity Results:", chunk_results)
    # Plot the combined capacity results
    print("\nGenerating plot...")
    plot_capacity_results_bar(capacity_results)
    plot_capacity_results_bar(
        chunks_per_second_results,
        ylabel="Chunks per Second",
        title="Chunks per Second Comparison",
        legend_label="Average Chunks per Second",
        output_filename="chunks_per_second_comparison.png",
    )
    plot_capacity_results_bar(
        byte_per_chunk_results,
        ylabel="Bytes per Chunk",
        title="Bytes per Chunk Comparison",
        legend_label="Average Bytes per Chunk",
        output_filename="bytes_per_chunk_comparison.png",
    )
    plot_chunks_as_count_bar(chunk_results)
    plot_chunks_as_count_bar(
        correctness_results,
        ylabel="Correctness",
        title="Correctness Comparison",
        legend_label="Average Correctness",
        output_filename="correctness_comparison.png",
    )

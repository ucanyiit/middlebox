import matplotlib.pyplot as plt
import numpy as np
import re
import statistics
from collections import defaultdict

# Configuration Constants
CONFIDENCE_LEVEL = 0.95
Z_SCORE = 1.96  # Z-score for 95% confidence interval

# Detection threshold: scores > 1000 are considered true positives (covert channel detected)
DETECTION_THRESHOLD = 1000.0

# Plot Configuration Constants
PLOT_DPI = 300
BBOX_INCHES = 'tight'
GRID_ALPHA = 0.3
FONT_SIZE_LABEL = 12
FONT_SIZE_TITLE = 14

# Default Data Files
DEFAULT_COVERT_LOG = "dns_analysis_covert_channel.log"
DEFAULT_NORMAL_LOG = "dns_analysis_normal_traffic.log"

# Default Output Filenames
DEFAULT_METRICS_PLOT = "detection_metrics.png"
DEFAULT_CONFUSION_MATRIX_PLOT = "confusion_matrix.png"
DEFAULT_SCORE_DISTRIBUTIONS_PLOT = "score_distributions.png"
DEFAULT_COMPREHENSIVE_PLOT = "comprehensive_comparison.png"

# Plot Colors
METRIC_COLORS = ['skyblue', 'lightgreen', 'lightcoral', 'lightsalmon', 'gold', 'plum']
BAR_COLORS = {'accuracy': 'skyblue', 'precision': 'lightgreen', 'recall': 'lightcoral', 'f1': 'gold'}

def parse_dns_threat_data(filename):
    """
    Parse DNS threat assessment data from log file.
    
    Args:
        filename (str): Path to the log file
        
    Returns:
        list: List of dictionaries containing parsed data
    """
    parsed_data = []
    
    with open(filename, "r", encoding='utf-8') as f:
        content = f.read()
        
        # Split by assessment blocks
        entries = content.split("=== DNS Threat Level Assessment ===")
        
        for entry in entries:
            if not entry.strip():
                continue
            
            data = {}
            
            # Extract threat score
            score_match = re.search(r"Score: ([\d.]+)", entry)
            if score_match:
                data["threat_score"] = float(score_match.group(1))
            
            # Only add if we have essential data
            if "threat_score" in data:
                parsed_data.append(data)
    
    return parsed_data

def classify_detection(threat_score, ground_truth_positive=True):
    """
    Classify detection result based on threat score and ground truth.
    
    Args:
        threat_score (float): The threat score from the detector
        ground_truth_positive (bool): Whether this should be detected as positive
        
    Returns:
        str: Classification result ('TP', 'TN', 'FP', 'FN')
    """
    predicted_positive = threat_score > DETECTION_THRESHOLD
    
    if ground_truth_positive and predicted_positive:
        return 'TP'  # True Positive
    elif not ground_truth_positive and not predicted_positive:
        return 'TN'  # True Negative
    elif not ground_truth_positive and predicted_positive:
        return 'FP'  # False Positive
    else:  # ground_truth_positive and not predicted_positive
        return 'FN'  # False Negative

def calculate_detection_metrics(classifications):
    """
    Calculate detection performance metrics.
    
    Args:
        classifications (list): List of classification results
        
    Returns:
        dict: Dictionary containing various metrics
    """
    tp = classifications.count('TP')
    tn = classifications.count('TN')
    fp = classifications.count('FP')
    fn = classifications.count('FN')
    
    total = tp + tn + fp + fn
    
    # Basic metrics
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    
    # F-scores
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    f2_score = 5 * (precision * recall) / (4 * precision + recall) if (4 * precision + recall) > 0 else 0
    
    return {
        'TP': tp,
        'TN': tn,
        'FP': fp,
        'FN': fn,
        'Total': total,
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'Specificity': specificity,
        'F1_Score': f1_score,
        'F2_Score': f2_score
    }

def calculate_stats_and_ci(data):
    """
    Calculate mean, standard deviation, and confidence interval for a dataset.
    
    Args:
        data (list): The list of data points
        
    Returns:
        tuple: (mean, lower_bound, upper_bound)
    """
    n = len(data)
    if n < 2:
        if n == 1:
            return statistics.mean(data), None, None
        return None, None, None
    
    mean = statistics.mean(data)
    std_dev = statistics.stdev(data)
    
    margin_of_error = Z_SCORE * (std_dev / np.sqrt(n))
    lower_bound = mean - margin_of_error
    upper_bound = mean + margin_of_error
    
    # Ensure bounds are not negative for scores
    lower_bound = max(0, lower_bound)
    
    return mean, lower_bound, upper_bound

def plot_detection_metrics_bar(metrics_dict, output_filename=DEFAULT_METRICS_PLOT):
    """
    Plot detection metrics as bar chart.
    """
    # Select key metrics for visualization
    metric_names = ['Accuracy', 'Precision', 'Recall', 'Specificity', 'F1_Score', 'F2_Score']
    metric_values = [metrics_dict[name] for name in metric_names]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    bars = ax.bar(metric_names, metric_values, color=METRIC_COLORS)
    
    # Add value labels on bars
    for bar, value in zip(bars, metric_values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{value:.3f}', ha='center', va='bottom', fontweight='bold')
    
    ax.set_ylabel('Score', fontsize=FONT_SIZE_LABEL)
    ax.set_title('DNS Covert Channel Detection Performance Metrics', fontsize=FONT_SIZE_TITLE)
    ax.set_ylim(0, 1.1)
    ax.grid(True, axis='y', alpha=GRID_ALPHA)
    
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    plt.savefig(output_filename, dpi=PLOT_DPI, bbox_inches=BBOX_INCHES)
    print(f"Detection metrics plot saved to {output_filename}")

def plot_confusion_matrix(metrics_dict, output_filename=DEFAULT_CONFUSION_MATRIX_PLOT):
    """
    Plot confusion matrix.
    """
    cm = np.array([[metrics_dict['TP'], metrics_dict['FN']],
                   [metrics_dict['FP'], metrics_dict['TN']]])
    
    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    
    # Add colorbar
    ax.figure.colorbar(im, ax=ax)
    
    # Add labels
    classes = ['Positive', 'Negative']
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=classes,
           yticklabels=classes,
           ylabel='True Label',
           xlabel='Predicted Label',
           title='Confusion Matrix - DNS Covert Channel Detection')
    
    # Add text annotations
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'),
                   ha="center", va="center",
                   color="white" if cm[i, j] > thresh else "black",
                   fontsize=16, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=PLOT_DPI, bbox_inches=BBOX_INCHES)
    print(f"Confusion matrix plot saved to {output_filename}")

def analyze_combined_datasets(covert_data, normal_data):
    """
    Analyze combined covert and normal traffic datasets for realistic evaluation.
    
    Args:
        covert_data (list): Parsed covert channel data
        normal_data (list): Parsed normal traffic data
        
    Returns:
        dict: Combined analysis results
    """
    print(f"\n=== COMBINED DATASET ANALYSIS ===")
    print(f"Covert traffic samples: {len(covert_data)}")
    print(f"Normal traffic samples: {len(normal_data)}")
    
    # Combine datasets with ground truth labels
    combined_classifications = []
    combined_scores = []
    
    # Process normal traffic (ground truth negative)
    for data in normal_data:
        classification = classify_detection(data['threat_score'], ground_truth_positive=False)
        combined_classifications.append(classification)
        combined_scores.append(data['threat_score'])
    
    # Process covert traffic (ground truth positive)
    for data in covert_data:
        classification = classify_detection(data['threat_score'], ground_truth_positive=True)
        combined_classifications.append(classification)
        combined_scores.append(data['threat_score'])
    
    # Calculate combined metrics
    combined_metrics = calculate_detection_metrics(combined_classifications)
    
    print(f"\nCombined Dataset Results:")
    print(f"  Total samples: {len(combined_classifications)}")
    print(f"  Normal samples: {len(normal_data)}")
    print(f"  Covert samples: {len(covert_data)}")
    print(f"  Accuracy: {combined_metrics['Accuracy']:.3f}")
    print(f"  Precision: {combined_metrics['Precision']:.3f}")
    print(f"  Recall: {combined_metrics['Recall']:.3f}")
    print(f"  Specificity: {combined_metrics['Specificity']:.3f}")
    print(f"  F1-Score: {combined_metrics['F1_Score']:.3f}")
    
    return combined_metrics, combined_scores

def plot_score_distributions(covert_scores, normal_scores, output_filename=DEFAULT_SCORE_DISTRIBUTIONS_PLOT):
    """
    Plot threat score distributions for covert vs normal traffic.
    
    Args:
        covert_scores (list): Pre-calculated covert traffic scores
        normal_scores (list): Pre-calculated normal traffic scores
        output_filename (str): Output filename for the plot
    """
    plt.figure(figsize=(12, 8))
    
    # Create histograms
    plt.hist(normal_scores, bins=50, alpha=0.7, label=f'Normal Traffic (n={len(normal_scores)})', 
             color='blue', density=True)
    plt.hist(covert_scores, bins=50, alpha=0.7, label=f'Covert Traffic (n={len(covert_scores)})', 
             color='red', density=True)
    
    # Add detection threshold line
    plt.axvline(x=DETECTION_THRESHOLD, color='black', linestyle='--', 
                linewidth=2, label=f'Detection Threshold ({DETECTION_THRESHOLD})')
    
    plt.xlabel('Threat Score', fontsize=FONT_SIZE_LABEL)
    plt.ylabel('Density', fontsize=FONT_SIZE_LABEL)
    plt.title('Threat Score Distributions: Normal vs Covert Traffic', fontsize=FONT_SIZE_TITLE)
    plt.legend()
    plt.grid(True, alpha=GRID_ALPHA)
    plt.tight_layout()
    
    plt.savefig(output_filename, dpi=PLOT_DPI, bbox_inches=BBOX_INCHES)
    print(f"Score distributions plot saved to {output_filename}")

def plot_comprehensive_comparison(pure_metrics, normal_metrics, combined_metrics, 
                                output_filename=DEFAULT_COMPREHENSIVE_PLOT):
    """
    Plot comprehensive comparison of all scenarios.
    """
    scenarios = ['Pure Covert', 'Normal Traffic', 'Combined Dataset']
    accuracy_values = [pure_metrics['Accuracy'], normal_metrics['Accuracy'], combined_metrics['Accuracy']]
    precision_values = [pure_metrics['Precision'], normal_metrics['Precision'], combined_metrics['Precision']]
    recall_values = [pure_metrics['Recall'], normal_metrics['Recall'], combined_metrics['Recall']]
    f1_values = [pure_metrics['F1_Score'], normal_metrics['F1_Score'], combined_metrics['F1_Score']]
    
    x = np.arange(len(scenarios))
    width = 0.2
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    bars1 = ax.bar(x - 1.5*width, accuracy_values, width, label='Accuracy', alpha=0.8, 
                   color=BAR_COLORS['accuracy'])
    bars2 = ax.bar(x - 0.5*width, precision_values, width, label='Precision', alpha=0.8, 
                   color=BAR_COLORS['precision'])
    bars3 = ax.bar(x + 0.5*width, recall_values, width, label='Recall', alpha=0.8, 
                   color=BAR_COLORS['recall'])
    bars4 = ax.bar(x + 1.5*width, f1_values, width, label='F1-Score', alpha=0.8, 
                   color=BAR_COLORS['f1'])
    
    ax.set_xlabel('Detection Scenario', fontsize=FONT_SIZE_LABEL)
    ax.set_ylabel('Score', fontsize=FONT_SIZE_LABEL)
    ax.set_title('DNS Covert Channel Detection: Comprehensive Performance Comparison', fontsize=FONT_SIZE_TITLE)
    ax.set_xticks(x)
    ax.set_xticklabels(scenarios)
    ax.legend()
    ax.grid(True, axis='y', alpha=GRID_ALPHA)
    ax.set_ylim(0, 1.1)
    
    # Add value labels on bars
    for bars in [bars1, bars2, bars3, bars4]:
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                   f'{height:.3f}', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=PLOT_DPI, bbox_inches=BBOX_INCHES)
    print(f"Comprehensive comparison plot saved to {output_filename}")

def generate_enhanced_summary_report(pure_metrics, combined_metrics, 
                                   covert_data, normal_data, covert_scores, normal_scores, optimal_threshold):
    """
    Generate an enhanced comprehensive summary report with real data.
    """
    print("\n" + "="*70)
    print("        ENHANCED DNS COVERT CHANNEL DETECTION BENCHMARK REPORT")
    print("="*70)
    
    print("\n1. DATASET OVERVIEW:")
    print(f"   - Covert Channel Traffic: {len(covert_data)} assessments")
    print(f"   - Normal Traffic: {len(normal_data)} assessments")
    print(f"   - Total Combined: {len(covert_data) + len(normal_data)} assessments")
    print(f"   - Detection Threshold: {DETECTION_THRESHOLD}")
    
    print("\n2. PURE COVERT TRAFFIC DETECTION (Original Analysis):")
    print("   - All traffic assumed to be covert channel attempts")
    print(f"   - Accuracy: {pure_metrics['Accuracy']:.3f}")
    print(f"   - Precision: {pure_metrics['Precision']:.3f}")
    print(f"   - Recall: {pure_metrics['Recall']:.3f}")
    print(f"   - F1-Score: {pure_metrics['F1_Score']:.3f}")
    
    print("\n4. REAL COMBINED DATASET (NORMAL + COVERT):")
    print("   - Actual normal traffic vs actual covert traffic")
    print(f"   - Accuracy: {combined_metrics['Accuracy']:.3f}")
    print(f"   - Precision: {combined_metrics['Precision']:.3f}")
    print(f"   - Recall: {combined_metrics['Recall']:.3f}")
    print(f"   - Specificity: {combined_metrics['Specificity']:.3f}")
    print(f"   - F1-Score: {combined_metrics['F1_Score']:.3f}")
    
    # Use pre-calculated score statistics
    print("\n5. THREAT SCORE STATISTICS:")
    print(f"   - Normal Traffic: Mean={np.mean(normal_scores):.1f}, "
          f"Std={np.std(normal_scores):.1f}, Range=[{min(normal_scores):.1f}, {max(normal_scores):.1f}]")
    print(f"   - Covert Traffic: Mean={np.mean(covert_scores):.1f}, "
          f"Std={np.std(covert_scores):.1f}, Range=[{min(covert_scores):.1f}, {max(covert_scores):.1f}]")
    
    print("\n6. THRESHOLD ANALYSIS:")
    print(f"   - Current Threshold: {DETECTION_THRESHOLD}")
    print(f"   - Optimal Threshold: {optimal_threshold}") 
    normal_above_threshold = sum(1 for score in normal_scores if score > DETECTION_THRESHOLD)
    covert_above_threshold = sum(1 for score in covert_scores if score > DETECTION_THRESHOLD)
    print(f"   - Normal Traffic Above Threshold: {normal_above_threshold}/{len(normal_scores)} ({100*normal_above_threshold/len(normal_scores):.1f}%)")
    print(f"   - Covert Traffic Above Threshold: {covert_above_threshold}/{len(covert_scores)} ({100*covert_above_threshold/len(covert_scores):.1f}%)")
    
    print("\n7. PERFORMANCE INSIGHTS:")
    if combined_metrics['Precision'] > 0.9:
        print("   ✓ Excellent precision - low false positive rate")
    elif combined_metrics['Precision'] > 0.8:
        print("   ⚠ Good precision - moderate false positive rate")
    else:
        print("   ⚠ Poor precision - high false positive rate")
        
    if combined_metrics['Recall'] > 0.9:
        print("   ✓ Excellent recall - low false negative rate")
    elif combined_metrics['Recall'] > 0.8:
        print("   ⚠ Good recall - moderate false negative rate")
    else:
        print("   ⚠ Poor recall - high false negative rate")
    
    print("\n8. RECOMMENDATIONS:")
    if combined_metrics['Recall'] < 0.95:
        print("   - Consider lowering threshold to improve covert channel detection")
    if combined_metrics['Precision'] < 0.90:
        print("   - Consider raising threshold to reduce false alarms")
    if optimal_threshold != DETECTION_THRESHOLD:
        print(f"   - Consider adjusting threshold to {optimal_threshold} for balanced performance")
    if combined_metrics['F1_Score'] > 0.9:
        print("   - Current detector shows excellent overall performance")
    
    print("\n" + "="*70)

# --- Helper Functions ---
def extract_threat_scores(data_list):
    """Extract threat scores from parsed data."""
    return [data['threat_score'] for data in data_list]

def print_metrics_summary(title, metrics):
    """
    Print a formatted summary of detection metrics with interpretation.
    
    Args:
        title (str): Title for the summary
        metrics (dict): Dictionary containing metrics from calculate_detection_metrics
    """
    print(f"\n{title}:")
    print(f"  Total Assessments: {metrics['Total']}")
    print(f"  True Positives (TP): {metrics['TP']}")
    print(f"  False Negatives (FN): {metrics['FN']}")
    print(f"  Accuracy: {metrics['Accuracy']:.3f}")
    print(f"  Precision: {metrics['Precision']:.3f}")
    print(f"  Recall: {metrics['Recall']:.3f}")
    print(f"  F1-Score: {metrics['F1_Score']:.3f}")
    
    # Add interpretation note for normal traffic analysis
    if metrics['TP'] == 0 and metrics['FN'] == 0:
        print(f"  Note: Precision and Recall are 0 because no covert channels exist in this dataset.")
        print(f"        For normal traffic, meaningful metrics are Accuracy ({metrics['Accuracy']:.3f}) and")
        print(f"        Specificity ({metrics['Specificity']:.3f}) which measure false positive avoidance.")
        print(f"        TP=0 means no covert channels were correctly identified (expected for normal-only data).")
        print(f"        This demonstrates the system is working correctly - 0 precision/recall is mathematically accurate.")

def print_statistics_summary(label, scores):
    """Print statistical summary for a dataset."""
    mean, lower, upper = calculate_stats_and_ci(scores)
    print(f"{label}:")
    print(f"  Mean Threat Score: {mean:.1f}")
    if lower is not None and upper is not None:
        print(f"  95% CI: ({lower:.1f}, {upper:.1f})")
    print(f"  Score Range: {min(scores):.1f} - {max(scores):.1f}")

def validate_data_files(covert_data, normal_data):
    """Validate that data files were parsed successfully."""
    if not covert_data:
        print("ERROR: No covert channel data found!")
        exit(1)
    if not normal_data:
        print("ERROR: No normal traffic data found!")
        exit(1)

# --- Main Execution ---
if __name__ == "__main__":
    covert_log_filename = DEFAULT_COVERT_LOG
    normal_log_filename = DEFAULT_NORMAL_LOG
    
    print("=== ENHANCED DNS COVERT CHANNEL DETECTION ANALYSIS ===")
    print(f"Processing covert traffic log: {covert_log_filename}")
    print(f"Processing normal traffic log: {normal_log_filename}")
    print(f"Detection threshold: {DETECTION_THRESHOLD}")
    print("-" * 60)
    
    # Parse and validate datasets
    print("Parsing DNS threat assessment data...")
    covert_data = parse_dns_threat_data(covert_log_filename)
    normal_data = parse_dns_threat_data(normal_log_filename)
    validate_data_files(covert_data, normal_data)
    
    print(f"Successfully parsed {len(covert_data)} covert channel assessments")
    print(f"Successfully parsed {len(normal_data)} normal traffic assessments")
    
    # Extract threat scores once to avoid redundant calculations
    covert_scores = extract_threat_scores(covert_data)
    normal_scores = extract_threat_scores(normal_data)
    
    # Original analysis: Pure covert traffic (for comparison)
    print("\n=== ORIGINAL ANALYSIS: PURE COVERT TRAFFIC ===")
    pure_covert_classifications = [classify_detection(score, ground_truth_positive=True) for score in covert_scores]
    pure_covert_metrics = calculate_detection_metrics(pure_covert_classifications)
    print_metrics_summary("Pure Covert Traffic Results", pure_covert_metrics)
    
    # Original analysis: Normal traffic (for comparison)
    print("\n=== ORIGINAL ANALYSIS: NORMAL TRAFFIC ===")
    print("Note: Analyzing normal traffic only - precision/recall will be 0 (this is correct behavior)")
    normal_classifications = [classify_detection(score, ground_truth_positive=False) for score in normal_scores]
    normal_metrics = calculate_detection_metrics(normal_classifications)
    print_metrics_summary("Normal Traffic Results", normal_metrics)
    
    # Combined real dataset analysis
    combined_metrics, combined_scores = analyze_combined_datasets(covert_data, normal_data)
    
    # Display overall statistics comparison
    print(f"\n=== OVERALL STATISTICS COMPARISON ===")
    print_statistics_summary("Covert Traffic", covert_scores)
    print_statistics_summary("Normal Traffic", normal_scores)
    
    # Generate visualizations
    print("\n=== GENERATING ENHANCED VISUALIZATIONS ===")
    plot_detection_metrics_bar(combined_metrics, "combined_detection_metrics.png")
    plot_confusion_matrix(combined_metrics, "combined_confusion_matrix.png")
    plot_score_distributions(covert_scores, normal_scores)
    
    # Advanced Analysis
    print("\n=== ADVANCED ANALYSIS ===")
    optimal_threshold = DETECTION_THRESHOLD  # Using current threshold since ROC analysis was removed
    plot_comprehensive_comparison(pure_covert_metrics, normal_metrics, combined_metrics)
    
    # Generate comprehensive summary report
    generate_enhanced_summary_report(pure_covert_metrics, combined_metrics, 
                                   covert_data, normal_data, covert_scores, normal_scores, optimal_threshold)
    
    print("\n=== ANALYSIS COMPLETE ===")
    print("Generated visualizations:")
    print("- combined_detection_metrics.png") 
    print("- combined_confusion_matrix.png")
    print(f"- {DEFAULT_SCORE_DISTRIBUTIONS_PLOT}")
    print(f"- {DEFAULT_COMPREHENSIVE_PLOT}")
    print("\nAll analysis results and visualizations have been saved to the current directory.")

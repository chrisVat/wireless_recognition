import pyshark
import os 
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime


runs_folder = "keystroke_runs/"
RUN_ID = "1"

cache = "run_cache/"
ADDR = "2c:6d:c1:12:9d:28"
ADDR = "b4:17:a8:3d:fc:57"


def load_key_presses():
    df = pd.read_csv(f"{runs_folder}run_{RUN_ID}/run_{RUN_ID}_presses.csv")
    timestamps= np.array(df['timestamps'].tolist())
    return timestamps

def get_device_offset():
    with open(f"{runs_folder}run_{RUN_ID}/run_{RUN_ID}_offset.txt", "r") as f:
        offset = float(f.read())
    return offset


def get_absolute_starting_time():
    result_file = None
    for file in os.listdir(f"{runs_folder}run_{RUN_ID}/"):
        if file.startswith(f"run_{RUN_ID}_") and file.endswith(".wav"):
            result_file = file
            break
    time_str = result_file.split(f"run_{RUN_ID}_")[1].split(".wav")[0]
    date_format = "%Y%m%d_%H%M%S_%f"

    # Add trailing zeros to convert milliseconds to microseconds (3 digits to 6 digits)
    if len(time_str.split('_')[-1]) == 3:
        time_str = time_str[:-3] + time_str[-3:] + "000"  # Add zeros to make it microseconds

    # Convert the string to a datetime object
    date_obj = datetime.strptime(time_str, date_format)
    return date_obj.timestamp()

def get_end_time():
    with open(f"{runs_folder}run_{RUN_ID}/run_{RUN_ID}_record_len.txt", "r") as f:
        record_len = float(f.read())
    
    with open(f"{runs_folder}run_{RUN_ID}/run_{RUN_ID}_endtime.txt", "r") as f:
        endtime = float(f.read())
    
    return record_len, endtime  

def combine_counts(counts, min_amount=23):
    widths = []
    count_idxs = []
    increased = 0
    for i in range(len(counts) - 1, 0, -1):        
        if counts[i] > 0 and counts[i - 1] > 0:  
            counts[i - 1] += counts[i]  
            counts[i] = 0 
            increased += 1
        elif counts[i] > min_amount and counts[i - 1] == 0:
            increased += 1
            if increased > 0:
                widths.append(increased)
                count_idxs.append(i)
            counts[i] = counts[i] / increased
            increased = 0
        else:
            increased = 0
            counts[i] = 0
    if increased > 0:
        widths.append(increased)
        count_idxs.append(0)

    # reverse widths
    widths = widths[::-1]
    count_idxs = count_idxs[::-1]
    return counts, widths, count_idxs

def combine_counts_2(counts):
    widths = []
    count_idxs = []

    i = 0
    while i < len(counts):
        if counts[i] > 0: 
            cur_idx = i
            max_seen = 0
            best_idx = i
            total = 0
            group_size = 0
            while cur_idx < len(counts) and counts[cur_idx] > 0:
                if counts[cur_idx] > max_seen:
                    max_seen = counts[cur_idx]
                    best_idx = cur_idx
                group_size += 1
                total += counts[cur_idx]
                counts[cur_idx] = 0
                cur_idx += 1
            
            widths.append(group_size)
            counts[best_idx] = total
            count_idxs.append(best_idx)
            i = cur_idx
        i+=1           

    return counts, widths, count_idxs

def find_enters(aggregate_counts, counts, burst_idxs, bin_size=0.05, thresh=400):
    for i in range(len(burst_idxs)):
        if burst_idxs[i] == 0:
            continue
        if aggregate_counts[burst_idxs[i]] > thresh:
            cur_idx = burst_idxs[i]
            while cur_idx >= 0 and counts[cur_idx] > 0:
                cur_idx -= 1
            aggregate_counts[cur_idx] = aggregate_counts[burst_idxs[i]]
            aggregate_counts[burst_idxs[i]] = 0
            burst_idxs[i] = cur_idx

    # assume single enter per 5
    enter_idx = None
    min_time_per_enter = 5
    for i in range(len(burst_idxs)):
        if aggregate_counts[burst_idxs[i]] > thresh:
            if enter_idx is None:
                enter_idx = burst_idxs[i]
            else:
                cur_idx = burst_idxs[i]
                time_since_enter = (bin_size * (cur_idx - enter_idx))
                if time_since_enter < min_time_per_enter:
                    aggregate_counts[burst_idxs[i]] = 0
                else:
                    enter_idx = cur_idx
    return aggregate_counts, burst_idxs

def remove_impossible_presses(aggregated_counts, burst_idxs, widths, min_time=0.45, bin_size=0.05):
    # start from the end, work back and remove any press that was within 400ms
    min_time_diff = 0.4
    min_index_diff = min_time_diff / bin_size

    bad_idxs = []
    prev_idx = None
    
    for i in range(len(burst_idxs)-1, 0, -1):
        if prev_idx is None:
            prev_idx = burst_idxs[i]
            continue
        if prev_idx - burst_idxs[i] < min_index_diff:
            aggregated_counts[burst_idxs[i]] = 0
            bad_idxs.append(i)
        else:
            prev_idx = burst_idxs[i]
    
    widths = [widths[i] for i in range(len(widths)) if i not in bad_idxs]
    burst_idxs = [burst_idxs[i] for i in range(len(burst_idxs)) if i not in bad_idxs]
    return aggregated_counts, burst_idxs, widths


def get_best_bins(counts, bin_edges, actual_keypress_times, bin_size=0.1):
    bin_size = 0.05
    aggregate_counts, widths, burst_idxs = combine_counts_2(counts.copy())

    min_aggregate = 23
    aggregate_counts[aggregate_counts < min_aggregate] = 0
    widths = [widths[i] for i in range(len(widths)) if aggregate_counts[burst_idxs[i]] >= min_aggregate]
    burst_idxs = [burst_idxs[i] for i in range(len(burst_idxs)) if aggregate_counts[burst_idxs[i]] >= min_aggregate]

    aggregate_counts, burst_idxs = find_enters(aggregate_counts, counts, burst_idxs)

    aggregate_counts, burst_idxs, widths = remove_impossible_presses(aggregate_counts, burst_idxs, widths, min_time=0.35, bin_size=bin_size)

    for i in range(len(widths)):
        if widths[i] < 3:
            aggregate_counts[burst_idxs[i]] = 0



    for i in range(len(widths)):
        if widths[i] > 3:
            print(f"Likely extras {widths[i]}")
        else:
            print(f"Keep it simple! {widths[i]}")

    plt.figure(figsize=(10, 6))
    plt.bar(bin_edges[:-1], aggregate_counts, width=bin_size, color='blue', alpha=0.7, label='Aggregated Packet Times')
    for actual_press in actual_keypress_times:
        plt.axvline(x=actual_press, color='red', linestyle='--', label='Real Press' if actual_press == actual_keypress_times[0] else "")

    plt.xlabel('Time (seconds)')
    plt.ylabel('Number of Packets')
    plt.title('Packet Times and Key Presses')
    plt.legend()
    plt.show()
    exit()




    return aggregate_counts



def main():
    if not os.path.exists(cache):
        os.makedirs(cache)
    wireshark_name = f"run_{RUN_ID}/run_{RUN_ID}.pcapng"
    cache_file_name = f"run_{RUN_ID}.npy"

    key_press_times = load_key_presses()
    # device_offset = get_device_offset()
    start_time = get_absolute_starting_time()
    
    record_len, end_time = get_end_time()

    print(f"Record Length: \t{record_len:.3f}")
    print(f"End Time: \t\t{end_time:.3f}")
    
    start_time = end_time - record_len

    key_sound_time = 0.2

    key_press_times = [start_time + key_press_time - key_sound_time for key_press_time in key_press_times]
    
    #exit()

    print(f"start time: \t\t{start_time:.3f}")
    #exit()

    #key_press_times = [key_press_time*1000 + start_time*1000 for key_press_time in key_press_times]
    #key_press_times = [key_press_time + start_time for key_press_time in key_press_times]

    #print(f"Offset: {device_offset}")
    print(f"Key Press Times: \t{key_press_times[-1]:.3f}")    
    #exit()


    if not os.path.exists(cache + cache_file_name): 
        filter = f"wlan.ta == {ADDR} || wlan.ra == {ADDR}"   
        capture = pyshark.FileCapture(runs_folder + wireshark_name, display_filter=filter)
        packet_times = [float(packet.sniff_timestamp) for packet in capture]
        packet_times = np.array(packet_times)
        np.save(cache + cache_file_name, packet_times)

    packet_times = np.load(cache + cache_file_name)
    #packet_times*=1000
    packet_times = packet_times[packet_times >= key_press_times[0]]
    packet_times = packet_times[packet_times <= key_press_times[-1]+5]

    print(f"Packet Times: \t\t{packet_times[-1]:.3f}")

    bin_size = 0.1
    bins = np.arange(packet_times.min(), packet_times.max() + bin_size, bin_size)

    counts, bin_edges = np.histogram(packet_times, bins=bins)

    proper_bins = get_best_bins(counts, bin_edges, key_press_times, bin_size)

    #exit()
    #aggregate_counts[aggregate_counts <= 23] = 0

    plt.figure(figsize=(10, 6))

    # plot aggregate counts
    plt.bar(bin_edges[:-1], proper_bins, width=bin_size, color='blue', alpha=0.7, label='Aggregated Packet Times')

    # Add vertical lines for key press times
    for key_press in key_press_times:
        plt.axvline(x=key_press, color='red', linestyle='--', label='Key Press' if key_press == key_press_times[0] else "")

    # Labels and title
    plt.xlabel('Time (seconds)')
    plt.ylabel('Number of Packets')
    plt.title('Packet Times and Key Presses')
    plt.legend()

    # Show the plot
    plt.show()


if __name__ == '__main__':
    main()
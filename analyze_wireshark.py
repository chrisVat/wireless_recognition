import pyshark
import os 
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd


keystroke_file = "keystrokes_google_limited_1728081389.9114387.csv" # google search
keystroke_file = "keystrokes_bank_limited_1728084829.2671618.csv" # bank login
cache = "saved_times/"
keystroke_folder = "keystrokes/"
wireshark_folder = "wireshark/"
ADDR = "2c:6d:c1:12:9d:28"


def load_key_presses():
    df = pd.read_csv(keystroke_folder + keystroke_file)
    timestamps= np.array(df['Timestamp'].tolist())
    return timestamps

def main():
    if not os.path.exists(cache):
        os.makedirs(cache)
    wireshark_name = "wireshark_" + keystroke_file.replace(".csv", ".pcapng")
    cache_file_name = "cached_" + keystroke_file.replace(".csv", ".npy")

    key_press_times = load_key_presses()

    if not os.path.exists(cache + cache_file_name): 
        filter = f"wlan.ta == {ADDR} || wlan.ra == {ADDR}"   
        capture = pyshark.FileCapture(wireshark_folder + wireshark_name, display_filter=filter)
        packet_times = [float(packet.sniff_timestamp) for packet in capture]
        packet_times = np.array(packet_times)
        np.save(cache + cache_file_name, packet_times)

    packet_times = np.load(cache + cache_file_name)
    
    bin_size = 0.05
    bins = np.arange(packet_times.min(), packet_times.max() + bin_size, bin_size)

    plt.figure(figsize=(10, 6))

    # Plot a histogram with half-second bins
    plt.hist(packet_times, bins=bins, color='blue', alpha=0.7, label='Packet Times')

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
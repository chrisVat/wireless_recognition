import pyshark
import os 
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from tqdm import tqdm


wireshark_file = "vr_search_5s_2.pcapng" # bank login
cache = "saved_times/"
wireshark_folder = "wireshark/"
ADDR = "b4:17:a8:3d:fc:57"
#REGENERATE_ANYWAY = True
REGENERATE_ANYWAY = False

FILTER_IDX = 10
FILTERS = [
    f"wlan.ta == b4:17:a8:3d:fc:57", # 0
    f"wlan.ra == b4:17:a8:3d:fc:57", # 1
    f"wlan.ta == b4:17:a8:3d:fc:57 || wlan.ra == b4:17:a8:3d:fc:57", # 2
    "((wlan.ta == b4:17:a8:3d:fc:57 || wlan.ra == b4:17:a8:3d:fc:57)) && (wlan.fc.type_subtype == 0x0028)", # 3
    "(wlan.ta == b4:17:a8:3d:fc:57) && (wlan.fc.type_subtype == 0x0028)", # 4
    "(wlan.ra == b4:17:a8:3d:fc:57) && (wlan.fc.type_subtype == 0x0028)", # 5
    f"(wlan.ta == b4:17:a8:3d:fc:57|| wlan.ra == b4:17:a8:3d:fc:57) && !(frame.len == 1562 || frame.len == 88 || frame.len == 76 || frame.len == 268 || frame.len == 178 || frame.len == 2718 || frame.len == 1558 || frame.len == 182 || frame.len == 70 || frame.len == 186 || frame.len == 514 || frame.len == 86 || frame.len == 190 || frame.len == 209 || frame.len == 699 || frame.len == 246 || frame.len == 202)", # 6
    f"wlan.ta == b4:17:a8:3d:fc:57 && !(frame.len == 1562 || frame.len == 88 || frame.len == 182 || frame.len == 86 || frame.len == 190 || frame.len == 699 || frame.len == 246 || frame.len == 268)", # 7
    "(wlan.ta == b4:17:a8:3d:fc:57 && wlan.fc.type_subtype == 0x0028) && !(frame.len==138||frame.len==170||frame.len==182||frame.len==190||frame.len==206||frame.len==213||frame.len==246||frame.len==268||frame.len==272||frame.len==284||frame.len==296||frame.len==297||frame.len==312||frame.len==348||frame.len==359||frame.len==360||frame.len==372||frame.len==378||frame.len==498||frame.len==607||frame.len==608||frame.len==671||frame.len==699||frame.len==813||frame.len==1097||frame.len==1249||frame.len==1282||frame.len==1382||frame.len==1383||frame.len==1408||frame.len==1562)",
    "wlan.ra == b4:17:a8:3d:fc:57 && wlan.fc.type_subtype == 0x001b", # 9
]

# (((wlan.ta == b4:17:a8:3d:fc:57)) && (wlan.fc.type_subtype == 0x0028)) && !(frame.len == 609 || frame.len == 2684 || frame.len == 1386 || frame.len == 268 || frame.len == 272 || frame.len == 1562 || frame.len == 220 || frame.len == 608 || frame.len == 182 || frame.len == 3028 || frame.len == 865 || frame.len == 2240 || frame.len == 182 || frame.len == 3028 || frame.len == 1558 || frame.len == 178)


# (wlan.ta == b4:17:a8:3d:fc:57 && wlan.fc.type_subtype == 0x0028) && !(frame.len == 499 || frame.len == 372 || frame.len == 1383 || frame.len == 936 || frame.len == 206 || frame.len == 680 || frame.len == 608 || frame.len == 671 || frame.len == 1408 || frame.len == 213 || frame.len == 1249 || frame.len == 1306 || frame.len == 699 || frame.len == 813 || frame.len == 348 ||frame.len == 182 ||frame.len == 272 || frame.len == 498 || frame.len == 1562)

# my custom filter 

# (wlan.ta == b4:17:a8:3d:fc:57 && wlan.fc.type_subtype == 0x0028) && !(frame.len==138||frame.len==170||frame.len==182||frame.len==190||frame.len==206||frame.len==213||frame.len==246||frame.len==268||frame.len==272||frame.len==284||frame.len==296||frame.len==297||frame.len==312||frame.len==348||frame.len==359||frame.len==360||frame.len==372||frame.len==378||frame.len==498||frame.len==607||frame.len==608||frame.len==671||frame.len==699||frame.len==813||frame.len==1097||frame.len==1249||frame.len==1282||frame.len==1382||frame.len==1383||frame.len==1408||frame.len==1562) 

techniques = {
    0: {
        "FILTER_IDX": 2,
        "min_hist": 20,
        "BIN_SIZE": 0.000038,
        "final_bin_size": 0.1
    },
    1: {
        "FILTER_IDX": 3,
        "min_hist": 20,
        "BIN_SIZE": 0.00005,
        "final_bin_size": 0.1
    }, # good
    2: {
        "FILTER_IDX": 4,
        "min_hist": 20,
        "BIN_SIZE": 0.00004,
        "final_bin_size": 0.1
    },
    3: {
        "FILTER_IDX": 6,
        "min_hist": 5,
        "BIN_SIZE": 0.005,
        "final_bin_size": 0.1
    }, # OK MAYVE?
    4: {
        "FILTER_IDX": 6,
        "min_hist": 5,
        "BIN_SIZE": 0.008,
        "final_bin_size": 0.1
    }, # Could be
    5: {
        "FILTER_IDX": 6,
        "min_hist": 5,
        "BIN_SIZE": 0.008,
        "final_bin_size": 0.1
    }, # better than 4?
    6: {
        "FILTER_IDX": 7,
        "min_hist": 5,
        "BIN_SIZE": 0.008,
        "final_bin_size": 0.1
    }, # its ok
    7: {
        "FILTER_IDX": 8,
        "min_hist": 0,
        "BIN_SIZE": 0.01,
        "final_bin_size": 0.1
    }, # 
    8: {
        "FILTER_IDX": 9,
        "min_hist": 3,
        "BIN_SIZE": 0.05,
        "final_bin_size": 0.1
    }, # 

}

# also works:
# (wlan.ta == b4:17:a8:3d:fc:57 && wlan.fc.type_subtype == 0x0028) && !(frame.len==138||frame.len==170||frame.len==182||frame.len==190||frame.len==206||frame.len==213||frame.len==246||frame.len==268||frame.len==272||frame.len==284||frame.len==296||frame.len==297||frame.len==312||frame.len==348||frame.len==359||frame.len==360||frame.len==372||frame.len==378||frame.len>500)

MIN_FINAL_HIST = 13

TECHNIQUE = 8

FILTER_IDX = techniques[TECHNIQUE]["FILTER_IDX"]
min_hist = techniques[TECHNIQUE]["min_hist"]
BIN_SIZE = techniques[TECHNIQUE]["BIN_SIZE"]
final_bin_size = techniques[TECHNIQUE]["final_bin_size"]


# large number of RTS. 
# wlan.ra == b4:17:a8:3d:fc:57 && wlan.fc.type_subtype == 0x001b
# 15, 20, 30, 45, (47), 55, 57k 60, 65, 

# filter on specific data sizes
# (wlan.ra == b4:17:a8:3d:fc:57 && wlan.fc.type_subtype == 0x0028 && frame.len > 200 && frame.len < 300)
# 5, 15, 20, 30, 45, 55, (57), (58.4) 60, (63), 65

# now trying wlan.ta == b4:17:a8:3d:fc:57 
# has potential wlan.ta == b4:17:a8:3d:fc:57 && frame.len < 89 && frame.len > 84


# wireshark, require at least 4, 100ms interval
# wlan.ra == b4:17:a8:3d:fc:57 && wlan.fc.type_subtype == 0x0019
# 5, 15, 20, 25, 30, 40, 44, 45, 50, 53.5, 55, 60, 65, 70, 
# missing 5, 10, 35, 75, 
# you really just want to sort on ta block acks.




def main():
    if not os.path.exists(cache):
        os.makedirs(cache)

    cache_file_name = "cached_" + wireshark_file[:-8] + "_" + str(FILTER_IDX) + ".npy"
    #analyze_irrelevant_packet_nums()
    #display_filter()

    if not os.path.exists(cache + cache_file_name) or REGENERATE_ANYWAY:
        filter = FILTERS[FILTER_IDX]
        capture = pyshark.FileCapture(wireshark_folder + wireshark_file, display_filter=filter)
        packet_times = [float(packet.sniff_timestamp) for packet in capture]
        packet_times = np.array(packet_times)
        np.save(cache + cache_file_name, packet_times)

    # Load packet times
    packet_times = np.load(cache + cache_file_name)
    # Make time start at 0
    packet_times -= packet_times[0]


    bins = np.arange(packet_times.min(), packet_times.max() + BIN_SIZE, BIN_SIZE)
    hist, bin_edges = np.histogram(packet_times, bins=bins)
    
    hist[hist < min_hist] = 0
    
    must_combine = int(final_bin_size // BIN_SIZE)
    
    if must_combine > 1:
        hist = np.array([sum(hist[i:i+must_combine]) for i in range(0, len(hist), must_combine)])
        bin_edges = bin_edges[::must_combine]
        bin_edges = np.append(bin_edges, bin_edges[-1] + final_bin_size)

    min_length = min(len(hist), len(bin_edges))
    hist = hist[:min_length]
    bin_edges = bin_edges[:min_length]
    
    hist[hist<MIN_FINAL_HIST] = 0

    plt.figure(figsize=(20, 12))
    # increase text size
    plt.rcParams.update({'font.size': 22})
    plt.bar(bin_edges, hist, width=final_bin_size, align='edge', label='Packet Times')

    # Add x ticks every 5 seconds
    plt.xticks([i for i in range(0, int(packet_times[-1]), 5)])

    # Labels and title
    plt.xlabel('Time (seconds)')
    plt.ylabel('Number of Packets')
    plt.title('Packet Times (Filtered and Re-binned)')
    plt.legend()
    plt.show()


def display_filter():
    result_1 = {76: 43, 86: 134, 88: 3185, 138: 1, 170: 61, 182: 266, 189: 12, 190: 132, 191: 58, 192: 12, 193: 2, 194: 8, 195: 5, 196: 13, 206: 38, 207: 1, 221: 10, 234: 7, 236: 3, 241: 1, 246: 115, 248: 29, 252: 1, 268: 115, 272: 50, 280: 1, 281: 1, 287: 2, 288: 7, 289: 17, 292: 4, 293: 2, 295: 1, 296: 79, 298: 1, 309: 1, 310: 1, 312: 84, 324: 1, 329: 1, 332: 1, 339: 1, 348: 88, 349: 1, 352: 1, 360: 2, 363: 1, 364: 1, 365: 1, 367: 1, 371: 2, 372: 3, 373: 12, 375: 1, 377: 2, 379: 2, 388: 1, 396: 1, 399: 1, 405: 2, 414: 1, 418: 1, 422: 5, 432: 1, 449: 1, 451: 1, 462: 1, 466: 1, 498: 2, 500: 1, 503: 1, 520: 1, 527: 1, 530: 1, 536: 3, 542: 1, 554: 1, 571: 1, 579: 1, 581: 1, 590: 1, 607: 1, 608: 9, 615: 1, 616: 1, 631: 1, 661: 1, 664: 1, 669: 1, 672: 1, 678: 1, 690: 1, 699: 128, 714: 1, 716: 1, 720: 1, 722: 1, 726: 2, 730: 1, 749: 1, 756: 1, 764: 1, 772: 1, 789: 1, 797: 1, 813: 2, 833: 1, 842: 1, 858: 1, 865: 1, 869: 1, 879: 1, 885: 1, 887: 1, 889: 2, 904: 2, 934: 1, 958: 1, 964: 1, 968: 1, 971: 1, 995: 1, 1004: 1, 1030: 2, 1044: 1, 1048: 1, 1057: 1, 1061: 1, 1073: 1, 1081: 2, 1082: 1, 1083: 3, 1093: 1, 1116: 1, 1148: 1, 1188: 1, 1212: 1, 1220: 1, 1297: 1, 1308: 1, 1338: 1, 1353: 2, 1354: 1, 1364: 1, 1377: 1, 1387: 7, 1388: 9, 1389: 14, 1390: 7, 1398: 1, 1404: 2, 1407: 1, 1408: 56, 1412: 1, 1432: 1, 1449: 1, 1451: 1, 1459: 1, 1469: 1, 1475: 2, 1476: 1, 1487: 1, 1489: 1, 1517: 1, 1549: 1, 1551: 1, 1562: 7110, 1571: 1, 1591: 1, 1627: 1, 1632: 1, 1651: 1, 1652: 12, 1659: 3, 1660: 2, 1661: 3, 1666: 1, 1683: 1, 1687: 1}
    result_2 = {1562: 7110, 88: 5888, 76: 2864, 268: 1639, 178: 1304, 2718: 824, 1558: 291, 182: 266, 70: 178, 186: 146, 514: 138, 86: 135, 190: 134, 209: 133, 699: 128, 246: 115, 202: 110, 348: 89, 312: 85, 296: 79, 663: 62, 170: 61, 303: 59, 191: 58, 1408: 56, 213: 55, 761: 51, 272: 50, 292: 41, 662: 41, 206: 38, 664: 35, 760: 31, 248: 29, 304: 29, 762: 24, 2714: 22, 1404: 20, 759: 19, 289: 17, 220: 16, 180: 15, 1389: 14, 192: 13, 196: 13, 310: 13, 189: 12, 300: 12, 373: 12, 1652: 12, 764: 11, 221: 10, 763: 10, 2710: 10, 184: 9, 371: 9, 608: 9, 1388: 9, 1492: 9, 179: 8, 185: 8, 194: 8, 226: 8, 439: 8, 2133: 8, 3028: 8, 234: 7, 288: 7, 556: 7, 1387: 7, 1390: 7, 868: 6, 195: 5, 422: 5, 204: 4, 396: 4, 451: 4, 758: 4, 1494: 4, 2423: 4, 236: 3, 252: 3, 349: 3, 372: 3, 536: 3, 773: 3, 1083: 3, 1131: 3, 1353: 3, 1354: 3, 1659: 3, 1661: 3, 2132: 3, 2419: 3, 177: 2, 183: 2, 193: 2, 283: 2, 287: 2, 293: 2, 360: 2, 377: 2, 379: 2, 405: 2, 455: 2, 461: 2, 462: 2, 467: 2, 498: 2, 532: 2, 552: 2, 588: 2, 726: 2, 813: 2, 889: 2, 904: 2, 964: 2, 1030: 2, 1081: 2, 1351: 2, 1356: 2, 1358: 2, 1475: 2, 1660: 2, 2243: 2, 2427: 2, 2446: 2, 138: 1, 154: 1, 203: 1, 207: 1, 217: 1, 237: 1, 241: 1, 266: 1, 270: 1, 280: 1, 281: 1, 285: 1, 295: 1, 298: 1, 299: 1, 308: 1, 309: 1, 317: 1, 324: 1, 329: 1, 332: 1, 333: 1, 337: 1, 339: 1, 342: 1, 346: 1, 352: 1, 363: 1, 364: 1, 365: 1, 366: 1, 367: 1, 375: 1, 376: 1, 388: 1, 399: 1, 414: 1, 418: 1, 432: 1, 449: 1, 466: 1, 475: 1, 479: 1, 500: 1, 503: 1, 520: 1, 521: 1, 527: 1, 528: 1, 530: 1, 542: 1, 554: 1, 560: 1, 571: 1, 579: 1, 580: 1, 581: 1, 589: 1, 590: 1, 593: 1, 607: 1, 615: 1, 616: 1, 631: 1, 661: 1, 669: 1, 672: 1, 678: 1, 690: 1, 707: 1, 714: 1, 716: 1, 720: 1, 722: 1, 730: 1, 749: 1, 756: 1, 757: 1, 765: 1, 769: 1, 772: 1, 774: 1, 782: 1, 789: 1, 797: 1, 803: 1, 820: 1, 833: 1, 840: 1, 842: 1, 851: 1, 858: 1, 865: 1, 869: 1, 872: 1, 879: 1, 885: 1, 887: 1, 934: 1, 958: 1, 966: 1, 968: 1, 971: 1, 977: 1, 995: 1, 1004: 1, 1044: 1, 1048: 1, 1057: 1, 1061: 1, 1071: 1, 1073: 1, 1082: 1, 1093: 1, 1109: 1, 1112: 1, 1116: 1, 1138: 1, 1148: 1, 1188: 1, 1206: 1, 1212: 1, 1220: 1, 1249: 1, 1297: 1, 1308: 1, 1325: 1, 1338: 1, 1349: 1, 1364: 1, 1377: 1, 1398: 1, 1407: 1, 1412: 1, 1432: 1, 1449: 1, 1451: 1, 1459: 1, 1469: 1, 1476: 1, 1487: 1, 1489: 1, 1497: 1, 1502: 1, 1517: 1, 1526: 1, 1530: 1, 1549: 1, 1551: 1, 1566: 1, 1571: 1, 1590: 1, 1591: 1, 1627: 1, 1632: 1, 1651: 1, 1654: 1, 1662: 1, 1666: 1, 1683: 1, 1687: 1, 1689: 1, 1747: 1, 1762: 1, 1886: 1, 1902: 1, 2001: 1, 2160: 1, 2170: 1, 2174: 1, 2201: 1, 2228: 1, 2300: 1, 2364: 1, 2409: 1, 2429: 1, 2450: 1, 2451: 1, 2475: 1, 2547: 1, 2641: 1, 2665: 1}

    result = result_2

    # size, count
    sorted_result = dict(sorted(result.items(), key=lambda item: item[1], reverse=True))
    print(sorted_result)
    
    # keep only with count over 40
    filtered_result = {k: v for k, v in sorted_result.items() if v > 100}
    # convert to filter
    filter = " || ".join([f"frame.len == {k}" for k in filtered_result.keys()])

    if result == result_1:
        filter = f"wlan.ta == b4:17:a8:3d:fc:57 && !({filter})"
    else:
        filter = f"(wlan.ta == b4:17:a8:3d:fc:57 || wlan.ra == b4:17:a8:3d:fc:57) && !({filter})"
    
    print("\n\n" + filter)
    
    exit()



def analyze_irrelevant_packet_nums():
    filter = f"wlan.ta == {ADDR} || wlan.ra == {ADDR}"
    capture = pyshark.FileCapture(wireshark_folder + wireshark_file, display_filter=filter)
    packet_sizes = []
    # iterate through packets, check time
    unwanted_int_ends = [3,4,5,8,9,0]

    num_processed = 0

    for packet in tqdm(capture, total=len(capture)):
        packet_time = int(float(packet.sniff_timestamp)) % 10
        num_processed += 1
        if packet_time not in unwanted_int_ends:
            packet_sizes.append(int(packet.length))
        #if num_processed > 10000:
        #    break
    packet_sizes = np.array(packet_sizes)
    # get count of each packet size, print them sorted
    unique, counts = np.unique(packet_sizes, return_counts=True)
    packet_size_count = dict(zip(unique, counts))
    sorted_packet_size_count = dict(sorted(packet_size_count.items(), key=lambda item: item[1], reverse=True))
    print(sorted_packet_size_count)
    exit()

    


if __name__ == '__main__':
    main()
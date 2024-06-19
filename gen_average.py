#!/usr/bin/env python3

import csv
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
# mpl.rcParams['mathtext.fontset'] = 'custom'
# mpl.rcParams['mathtext.rm'] = 'Bitstream Vera Sans'
# mpl.rcParams['mathtext.it'] = 'Bitstream Vera Sans:italic'
# mpl.rcParams['mathtext.bf'] = 'Bitstream Vera Sans:bold'
mpl.rcParams['mathtext.fontset'] = 'stix'
mpl.rcParams['axes.axisbelow'] = True
mpl.rcParams['axes.axisbelow'] = True
mpl.rcParams['axes.spines.right'] = False
mpl.rcParams['axes.spines.top'] = False
mpl.rcParams['font.family'] = 'STIXGeneral'
mpl.rcParams['font.size'] = 27

colors = [[min(1, 0.2+(i/256)*0.9), max(0.9-(i/256), 0), 0] for i in range(256)]
colourmap = ListedColormap(colors)

effectives_files = [
    "output/fairphone_one_day_analysis.csv",
    "output/google_one_day_analysis.csv",
    "output/huawei_one_day_analysis.csv",
    "output/motorola_one_day_analysis.csv",
    "output/oneplus_one_day_analysis.csv",
    "output/oppo_one_day_analysis.csv",
    "output/realme_one_day_analysis.csv",
    "output/samsung_one_day_analysis.csv",
    "output/vivo_one_day_analysis.csv",
    "output/xiaomi_one_day_analysis.csv",
]

effectives = []
includeds = []
for f in effectives_files:
    with open(f, "r") as f:
        reader = csv.reader(f, delimiter=';')
        effectives.extend([float(d[1]) for d in list(reader)[2:]])

effectives.sort(reverse=True)

normalize = mpl.colors.Normalize(vmin=0, vmax=26)
fine_data = []
FINE = 20
for e in effectives:
    fine_data.extend([e]*FINE)
def running_mean(dataset, window_size, times):
    window_size *= times
    dataset = [dataset[0]]*int(window_size*63/128) + dataset + [dataset[-1]]*int(window_size*1/2)
    result = []
    for i in range(len(dataset) - window_size + 1):
        window = dataset[i : i + window_size]
        window_average = sum(window) / window_size
        result.append(window_average)
    return result
times = 256
x = np.linspace(0, len(effectives)-1, len(effectives))
fine_data = running_mean(fine_data, FINE, times)
fine_x = np.linspace(0, len(effectives)-1, len(fine_data))
plt.figure(figsize=(8,5))
plt.xlabel("#images")
plt.ylabel("#one-day exploitation flows")
plt.yticks([0,5,10,15,20,25], fontsize=20)
plt.xticks(fontsize=20)
plt.ylim(0, 27)

length = len(effectives)-1
plt.xlim(-length*0.05, length*1.05)
plt.grid(axis = 'y', linestyle = '--', linewidth = 0.4)
plt.step(x,effectives, color="black", linewidth=1.5)
for i in range(len(fine_data)-1):
    plt.fill_between([fine_x[i], fine_x[i+1]],
                     [effectives[1+int(i/FINE)], effectives[1+int(i/FINE)]],
                     color=colourmap(normalize(fine_data[i+1])),
                     alpha=0.8,
                     linewidth=0.0)
average = sum(effectives)/len(effectives)
plt.annotate("{:.1f}".format(average), xy=(length*0.95,average+0.5), xytext=(length*0.95,average+0.5), fontsize=26)
plt.hlines(y=average, xmin=-length*0.05, xmax=length*1.05, colors="black", linestyle=(0, (7, 7, 1, 7)), linewidth=1.3)
plt.subplots_adjust(bottom=0.15, left=0.098, right=0.995, top=0.993)
plt.show()

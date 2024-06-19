#!/usr/bin/env python3

import matplotlib.pyplot as plt
import numpy as np
import matplotlib as mpl
from matplotlib.colors import ListedColormap
mpl.rcParams['mathtext.fontset'] = 'stix'
mpl.rcParams['axes.axisbelow'] = True
mpl.rcParams['axes.axisbelow'] = True
mpl.rcParams['axes.spines.right'] = False
mpl.rcParams['axes.spines.top'] = False
mpl.rcParams['font.family'] = 'STIXGeneral'
mpl.rcParams['font.size'] = 9

import csv

kernel_versions = [
    "v3.10",
    "v3.18",
    "v4.4",
    "v4.9",
    "v4.14",
    "v4.19",
    "v5.4",
    "v5.10",
    "v5.15",
    "v6.1"
]
fnames = [
    "fairphone_one_day_analysis_per_kernel_version.csv",
    "oneplus_one_day_analysis_per_kernel_version.csv",
    "google_one_day_analysis_per_kernel_version.csv",
    "motorola_one_day_analysis_per_kernel_version.csv",
    "huawei_one_day_analysis_per_kernel_version.csv",
    "realme_one_day_analysis_per_kernel_version.csv",
    "vivo_one_day_analysis_per_kernel_version.csv",
    "oppo_one_day_analysis_per_kernel_version.csv",
    "xiaomi_one_day_analysis_per_kernel_version.csv",
    "samsung_one_day_analysis_per_kernel_version.csv",
]

datas = []
names = []
for fname in fnames:
    with open("output/{}".format(fname), "r") as f:
        reader = csv.reader(f, delimiter=";")
        data = {}
        for kv in kernel_versions:
            data[kv] = 0
        for line in list(reader)[1:]:
            kv = line[0]
            countp = float(line[2])
            data[kv] = countp
    name = fname.split("_", 1)[0]
    name = name[0].upper() + name[1:]
    names.append(name)
    datas.append([100*d for d in list(data.values())])
datas = np.array(datas)
datas[datas == 0] = None
print(datas)

fig, ax = plt.subplots()
# im = ax.imshow(datas)

# colors = [[min(1, 0.2+(i/256)*0.9), max(0.9-(i/256), 0), 0] for i in range(256)]
# colourmap = ListedColormap(colors)
# heatmap = plt.pcolor(datas, cmap=colourmap)
heatmap = plt.pcolor(datas)
plt.colorbar(heatmap, format='%.0f%%')

# Show all ticks and label them with the respective list entries
ax.set_xticks(np.arange(len(kernel_versions))+0.5, labels=kernel_versions)
ax.set_yticks(np.arange(len(names))+0.5, labels=names)
ax.xaxis.set_tick_params(labelsize=12)
ax.yaxis.set_tick_params(labelsize=16)

# Rotate the tick labels and set their alignment.
plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
         rotation_mode="anchor")

# Loop over data dimensions and create text annotations.
for i in range(len(names)):
    for j in range(len(kernel_versions)):
        if datas[i][j] == 0:
            continue
        if datas[i][j] > 60:
            color="black"
        else:
            color="white"
        text = ax.text(j+0.5, i+0.5, "{:.1f}%".format(datas[i][j]),
                       ha="center", va="center", color=color)

fig.tight_layout()
plt.gca().collections[0].set_clim(0,100)
# plt.savefig("output/kernel_version_heatmap.pdf", dpi=300)
plt.show()


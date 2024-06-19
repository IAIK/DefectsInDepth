#!/usr/bin/env python3

import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
mpl.rcParams['mathtext.fontset'] = 'stix'
mpl.rcParams['axes.axisbelow'] = True
mpl.rcParams['axes.axisbelow'] = True
mpl.rcParams['axes.spines.right'] = False
mpl.rcParams['axes.spines.top'] = False
mpl.rcParams['font.family'] = 'STIXGeneral'
mpl.rcParams['font.size'] = 27

colors = [[min(1, 0.2+(i/256)*0.9), max(0.9-(i/256), 0), 0] for i in range(256)]
colourmap = ListedColormap(colors)

normalize = mpl.colors.Normalize(vmin=0, vmax=26)
x = np.linspace(0, 1, 2)
plt.figure(figsize=(8,5))
plt.xlabel("#images")
plt.ylabel("#one-day exploitation flows")
plt.yticks([0,5,10,15,20,25], fontsize=20)
plt.xticks([0,1], fontsize=20)
plt.ylim(0, 27)
plt.xlim(-0.05, 1.05)
plt.grid(axis = 'y', linestyle = '--', linewidth = 0.4)
# plt.plot(x, [4, 4], color="black", linewidth=1.5)
plt.fill_between([0, 1],
                 [4, 4],
                 color=colourmap(normalize(4)),
                 alpha=0.8,
                 linewidth=0.0)
plt.annotate(str(4), xy=(0.95,4.5), xytext=(0.95,4.5), fontsize=26)
plt.hlines(y=4, xmin=-0.05, xmax=1.05, colors="black", linestyle=(0, (7, 7, 1, 7)), linewidth=1.3)
plt.subplots_adjust(bottom=0.15, left=0.098, right=0.995, top=0.993)
plt.show()
# plt.savefig("output/ground_truth_one_day_analysis.png", dpi=100)

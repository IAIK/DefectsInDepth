#!/usr/bin/env python3

import argparse
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

parser = argparse.ArgumentParser(
    prog="gen_plot.py",
    description="Generates a nice one-day plot from a csv")

parser.add_argument(
    "csv_file",
    help="filename of the csv")
parser.add_argument(
    "--dotted",
    "-d",
    default="",
    type=str,
    help="second csv file for dotted lines")
parser.add_argument(
    "--outfile",
    "-o",
    default="",
    type=str,
    help="filename of output")
args = parser.parse_args()

dotted_data = []
with open(args.csv_file, "r") as f:
    reader = csv.reader(f, delimiter=';')
    data = [[float(d[0]), float(d[1])] for d in list(reader)[1:]]
    # print(data)
if args.dotted != "":
    # print("with dotted")
    with open(args.dotted, "r") as f:
        reader = csv.reader(f, delimiter=';')
        dotted_data = [[float(d[0]), float(d[1])] for d in list(reader)[1:]]
        # print(dotted_data)
if args.outfile != "" and args.outfile[-4:] != ".png":
    print("[!] shoulde be png")
    exit(-1) 

normalize = mpl.colors.Normalize(vmin=0, vmax=26)
fine_data = []
FINE = 20
for i in range(len(data)):
    d = data[i]
    fine_data.extend([d[1]]*FINE)
def running_mean(dataset, window_size, times):
    window_size *= times
    if times == 2:
        dataset = dataset + [dataset[-1]]*int(window_size*1/2)
    elif times == 4:
        dataset = [dataset[0]]*int(window_size*1/4) + dataset + [dataset[-1]]*int(window_size*1/2)
    elif times == 8:
        dataset = [dataset[0]]*int(window_size*3/8) + dataset + [dataset[-1]]*int(window_size*1/2)
    elif times == 16:
        dataset = [dataset[0]]*int(window_size*7/16) + dataset + [dataset[-1]]*int(window_size*1/2)
    elif times == 32:
        dataset = [dataset[0]]*int(window_size*15/32) + dataset + [dataset[-1]]*int(window_size*1/2)
    elif times == 64:
        dataset = [dataset[0]]*int(window_size*31/64) + dataset + [dataset[-1]]*int(window_size*1/2)
    result = []
    for i in range(len(dataset) - window_size + 1):
        window = dataset[i : i + window_size]
        window_average = sum(window) / window_size
        result.append(window_average)
    return result
if len(data) < 10:
    times = 2
elif len(data) < 20:
    times = 4
elif len(data) < 40:
    times = 8
elif len(data) < 80:
    times = 16
elif len(data) < 160:
    times = 32
else:
    times = 64
fine_data = running_mean(fine_data, FINE, times)
x = np.linspace(0, len(data)-1, len(fine_data))
# print(len(data))
# print(len(x))
# plt.plot(x, fine_data)
plt.figure(figsize=(8,5))
plt.xlabel("#images")
plt.ylabel("#one-day exploitation flows")
plt.yticks([0,5,10,15,20,25], fontsize=20)
plt.xticks(fontsize=20)
plt.ylim(0, 27)
length = len(data)-1
plt.xlim(-length*0.05, length*1.05)
plt.grid(axis = 'y', linestyle = '--', linewidth = 0.4)
plt.step([d[0] for d in data],[d[1] for d in data], color="black", linewidth=1)
if dotted_data != []:
    plt.step([d[0] for d in dotted_data],[d[1] for d in dotted_data], color="black", linewidth=1.5, linestyle=(0, (5,3)))
for i in range(len(fine_data)-1):
    plt.fill_between([x[i], x[i+1]],
                     [data[1+int(i/FINE)][1], data[1+int(i/FINE)][1]],
                     color=colourmap(normalize(fine_data[i+1])),
                     alpha=0.8,
                     linewidth=0.0)
average = sum([d[1] for d in data])/len(data)
plt.annotate("{:.1f}".format(average), xy=(length*0.95,average+0.5), xytext=(length*0.95,average+0.5), fontsize=26)
plt.axhline(y=average, color='black', linestyle=(0, (7, 7, 1, 7)), linewidth=1.5)
plt.subplots_adjust(bottom=0.15, left=0.098, right=0.995, top=0.993)
plt.show()
# plt.savefig(name, dpi=100)

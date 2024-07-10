#!/usr/bin/env python3

import argparse
import csv
import json
import os
import subprocess
import re
import numpy as np
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap

def check(vendor, count):
    path = "./{}/firmwares/".format(vendor)
    res = len([dir for dir in os.listdir(path) if os.path.isdir(path+dir)])
    print(res)
    assert res == count

check("fairphone", 3)
check("google", 26)
check("huawei", 119)
check("motorola", 104)
check("oneplus", 42)
check("oppo", 118)
check("realme", 135)
check("samsung", 164)
check("vivo", 144)
check("xiaomi", 144)

print("[+] Basic test success")

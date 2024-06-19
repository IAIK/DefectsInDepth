# Defects-in-Depth Artifacts

## What is Defects-in-Depth

We systematically analyze publicly available one-day exploits targeting the Android kernel over the past three years. We then demonstrate that integrating defense-in-depth mechanisms from the mainline Android kernel could mitigate 84.6% of these exploits. This percentage serves as the ground truth for how secure mobile devices could be if their kernels were up to date with these defense mechanisms enabled. In a subsequent analysis of 994 devices, we reveal that the level of security that is actually achieved is severely lacking compared to the mainline Android kernel. This achieved security varies significantly depending on the vendor, ranging from mitigating 28.8% to 54.6% of exploits, indicating a 4.62 to 2.95 (factors of (1-0.288)/(1-0.846) and (1-0.546)/(1-0.846), respectively) times worse scenario than the mainline kernel.


The artifacts include the dataset of 994 devices as well as the fully automated approach to determining the security achieved by vendor-specific kernels. For our dataset, we include the extracted kernel binaries with `kallsyms` of the top 7 vendors, i.e. Samsung, Xiaomi, Oppo, Vivo, Huawei, Realme and Motorola, along with Google, OnePlus and Fairphone, representing more than 84% of the global market. For the automated approach, we provide various Python and shell scripts to reproduce the results of our paper.

## Disclaimer

The artifacts do not perform any destructive steps. Crucially, while we provide the [dataset](https://todo) (size of about 45GB) of kernel binaries and `kallsyms` susceptible to one-days for the artifact evaluation, we do not open source these as they could be used in a malicious intent.

## Installation

TODO

## Publication

```
@inproceedings{Maar2024DefectsInDetph,
 author = {Lukas Maar and Florian Draschbacher and Lukas Lamster and Stefan Mangard},
 booktitle = {{USENIX Security}},
 title = {{Defects-in-Depth: Analyzing the Integration of Effective Defenses against One-Day Exploits in Android Kernels}},
 year = {2024}
}
```

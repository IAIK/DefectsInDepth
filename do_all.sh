#!/usr/bin/env bash
set -e
# for i in $(find config -type f -name find-protection.json | grep -v analysis/); do echo $i; ./evaluate.py $i; done
for i in $(find config -type f -name one-day-analysis.json | grep -v analysis/); do echo $i; ./evaluate.py $i; done
for i in $(find config -type f -name one-day-analysis-per-kernel-version.json); do echo $i; ./evaluate.py $i; done
./evaluate.py ./config/analysis/one-day-analysis-per-kernel-version-ieal.json
#!/usr/bin/env python

import sys
import pprint
from collections import defaultdict
import numpy

sys.path.append('./myplot')
import myplot

import plot

OPT=9

def size_transform(x):
    return float(x)/1024.0

def records(filepath):
    transform = plot.DATA_TRANSFORMS[OPT]
    with open(filepath, 'r') as f:
        for line in f:
            if line[0] != '#':
                fields = line.strip().split()

                scenario = '%s Mbps\n%0.1f kB' %\
                    (fields[1], size_transform(fields[0]))
                amazon = fields[2] == '1'
                scenario += '\nWide Area' if amazon else '\nControlled'

                mean = transform(fields[3])
                stddev = transform(fields[4])

                yield scenario, mean, stddev

def load_data(data, res_file, protocol):
    scenarios = []  # so we know the order
    for scenario, mean, stddev in records(res_file):
        data[scenario][protocol]['mean'] = mean
        data[scenario][protocol]['stddev'] = stddev

        scenarios.append(scenario)

    return scenarios

def plot_time_scenarios(machine, remote, result_files):
    out_filename, out_filepath = plot.outfile(OPT, remote, machine)

    ## LOAD DATA
    # scenario -> protocol -> data type -> value
    data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    scenarios = None
    
    protocols = []
    for protocol in plot.PROTOCOLS:
        if protocol not in result_files: continue
        protocols.append(protocol)
        filepath = result_files[protocol]
        print '[IN]', protocol, filepath

        scenarios = load_data(data, filepath, protocol)


    # filter scenarios (by index)
    use_indices = (0, 1, 2, 3, 5, 9, 13, 17)
    new_scenarios = [scenarios[i] for i in use_indices]
    scenarios = new_scenarios


    ## PLOT
    xs = []
    ys = []
    yerrs = []
    labels = []

    for protocol in protocols:
        xs.append(scenarios)
        means = []
        stddevs = []
        for scenario in scenarios:
            means.append(data[scenario][protocol]['mean'])
            stddevs.append(data[scenario][protocol]['stddev'])
        ys.append(means)
        yerrs.append(stddevs)
        labels.append(plot.LEGEND_STRINGS[protocol])

    print '[OUT]', out_filepath
    myplot.bar(xs, ys, yerrs=yerrs, labels=labels, xtick_label_rotation=0,\
        xtick_label_horizontal_alignment='center', ylabel=plot.Y_AXIS[OPT],\
        filename=out_filepath, **plot.MANUAL_ARGS[out_filename])

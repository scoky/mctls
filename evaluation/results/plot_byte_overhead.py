#!/usr/bin/env python

import sys
import pprint
from collections import defaultdict
import numpy

sys.path.append('./myplot')
import myplot

import plot

OPT=8


def records(filepath):
    transform = plot.DATA_TRANSFORMS[OPT]
    with open(filepath, 'r') as f:
        for line in f:
            if line[0] != '#':
                fields = line.strip().split()

                scenario = 'Ctxts: %s\nMbox: %s\n%0.0f kB' %\
                    (fields[0], fields[1], transform(fields[2]))

                total_bytes = transform(fields[3])
                app_total = transform(fields[4])
                padding_total = transform(fields[5])
                header_total = transform(fields[6])
                handshake_total = transform(fields[7])
                mac_total = transform(fields[8])
                alert_total = transform(fields[9])

                yield scenario, total_bytes, app_total, padding_total,\
                    header_total, handshake_total, mac_total, alert_total

def load_data(data, res_file, protocol):
    scenarios = []  # so we know the order
    for scenario, total_bytes, app_total, padding_total,\
        header_total, handshake_total, mac_total, alert_total,\
        in records(res_file):

        data[scenario][protocol]['Total'] = total_bytes
        data[scenario][protocol]['App Data'] = app_total
        data[scenario][protocol]['Padding'] = padding_total
        data[scenario][protocol]['Header'] = header_total
        data[scenario][protocol]['Handshake'] = handshake_total
        data[scenario][protocol]['MAC'] = mac_total

        scenarios.append(scenario)

    return scenarios

def plot_byte_scenarios(machine, remote, result_files):

    ## LOAD DATA
    # scenario -> protocol -> data type -> value
    data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    scenarios = None
    
    for protocol in plot.PROTOCOLS[OPT]:
        if protocol not in result_files: continue
        filepath = result_files[protocol]
        print '[IN]', protocol, filepath

        scenarios = load_data(data, filepath, protocol)

    #scenarios = data.keys()
    protocols = data[scenarios[0]].keys()



    ## PLOT

    ###
    ### PLOT 1: total bytes
    ###
    #xs = []
    #ys = []
    #labels = []

    #for protocol in protocols:
    #    xs.append(scenarios)
    #    vals = []
    #    for scenario in scenarios:
    #        vals.append(data[scenario][protocol]['total'])
    #    ys.append(vals)
    #    labels.append(plot.LEGEND_STRINGS[protocol])

    #myplot.bar(xs, ys, labels=labels, xtick_label_rotation=0,\
    #    xtick_label_horizontal_alignment='center', ylabel='Total Data Transmitted (kB)',\
    #    filename='./fig/bytes_total.pdf')
    
    
    ##
    ## PLOT 2: breakdown (header, handshake, app, ...)
    ##
    out_filename, out_filepath = plot.outfile(OPT, remote, machine)
    xs = []
    ys = []  # array of arrays of arrays: each protocol has an array containing arrays for byte types
    labels = []
    colors = []
    
    protocols = ('spp', 'ssl', 'fwd')
    #byte_types = ('Header', 'Padding', 'Handshake', 'MAC')
    byte_types = ('Handshake', 'MAC')

    # hack to chop off file siz3
    scenario_mod = []
    for scenario in scenarios:
        scenario_mod.append('\n'.join(scenario.split('\n')[0:2]))

    for protocol in protocols:
        xs.append(scenario_mod) 
        val_arrays = []  # one per byte type
        for byte_type in byte_types:
            vals = []
            for scenario in scenarios[0:-1]:
                vals.append(data[scenario][protocol][byte_type])
            val_arrays.append(vals)
        ys.append(val_arrays)
        labels.append(plot.LEGEND_STRINGS[protocol])

    # skip the colors used for the protocols to avoid confusion
    colors=[6, 9]

    print '[OUT]', out_filepath
    myplot.stackbar(xs, ys, labels=labels, xtick_label_rotation=0,\
        xtick_label_horizontal_alignment='center', ylabel=plot.Y_AXIS[OPT],\
        stackbar_pattern_labels=byte_types,\
        stackbar_colors_denote='segments',\
        colors=colors, height_scale=0.9, width_scale=1.2, grid='y',\
        filename=out_filepath, **plot.MANUAL_ARGS[out_filename])
    
    ##
    ## PLOT 3: overhead breakdown by percentage
    ##
    out_filename, out_filepath = plot.outfile(OPT, remote, machine, extra_tag='_percent')
    xs = []
    ys = []  # array of arrays of arrays: each protocol has an array containing arrays for byte types
    labels = []
    colors = []
    
    protocols = ('spp', 'ssl', 'fwd')
    #byte_types = ('Header', 'Padding', 'Handshake', 'MAC')
    byte_types = ('Handshake', 'MAC')

    for protocol in protocols:
        xs.append(scenarios)
        val_arrays = []  # one per byte type
        for byte_type in byte_types:
            vals = []
            for scenario in scenarios:
                as_percentage = data[scenario][protocol][byte_type] /\
                    float(data[scenario][protocol]['App Data']) * 100.0
                vals.append(as_percentage)
            val_arrays.append(vals)
        ys.append(val_arrays)
        labels.append(plot.LEGEND_STRINGS[protocol])

    # skip the colors used for the protocols to avoid confusion
    colors=[5, 8, 6, 9]

    print '[OUT]', out_filepath
    myplot.stackbar(xs, ys, labels=labels, xtick_label_rotation=0,\
        xtick_label_horizontal_alignment='center', ylabel='% of App Data Size',\
        stackbar_pattern_labels=byte_types,\
        stackbar_colors_denote='segments',\
        colors=colors, width_scale=1.4, grid='y',\
        filename=out_filepath, **plot.MANUAL_ARGS[out_filename])
    
    
    
    ##
    ## PLOT 4: handshake only, colors for protocols
    ##
    out_filename, out_filepath = plot.outfile(OPT, remote, machine, extra_tag='_handshake')
    xs = []
    ys = []  # array of arrays: each protocol has an array with handshake sizes for each scenario
    labels = []
    colors = []
    
    protocols = ('spp', 'ssl', 'fwd')

    # hack to chop off file siz3
    scenario_mod = []
    for scenario in scenarios:
        scenario_mod.append('\n'.join(scenario.split('\n')[0:2]))

    for protocol in protocols:
        xs.append(scenario_mod) 
        #val_arrays = []  # one per byte type
        handshake_sizes = []
        for scenario in scenarios[0:-1]:
            handshake_sizes.append(data[scenario][protocol]['Handshake'])
        ys.append(handshake_sizes)
        labels.append(plot.LEGEND_STRINGS[protocol])

    print '[OUT]', out_filepath
    myplot.bar(xs, ys, labels=labels, xtick_label_rotation=0,\
        xtick_label_horizontal_alignment='center', ylabel=plot.Y_AXIS[OPT],\
        height_scale=0.9, width_scale=1.2, grid='y',\
        #builds = [[], [1, 2], [0, 1, 2]],\
        filename=out_filepath, **plot.MANUAL_ARGS[out_filename])

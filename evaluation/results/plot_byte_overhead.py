#!/usr/bin/env python

import sys
import pprint
from collections import defaultdict

sys.path.append('./myplot')
import myplot



# configuration
SPP_FILE = './res_spp_byteOverhead_scenarios'
SSL_FILE = './res_ssl_byteOverhead_scenarios'
FWD_FILE = './res_fwd_byteOverhead_scenarios'


def data_size(string):
    return float(string)/1024.0


def records(filepath):
    with open(filepath, 'r') as f:
        for line in f:
            if line[0] != '#':
                fields = line.strip().split()

                scenario = 'Slice: %s\nMbox: %s\nFile: %0.0f kB' %\
                    (fields[0], fields[1], data_size(fields[2]))

                total_bytes = data_size(fields[3])
                app_total = data_size(fields[4])
                padding_total = data_size(fields[5])
                header_total = data_size(fields[6])
                handshake_total = data_size(fields[7])
                mac_total = data_size(fields[8])
                alert_total = data_size(fields[9])

                yield scenario, total_bytes, app_total, padding_total,\
                    header_total, handshake_total, mac_total, alert_total

def load_data(data, res_file, protocol):
    scenarios = []  # so we know the order
    for scenario, total_bytes, app_total, padding_total,\
        header_total, handshake_total, mac_total, alert_total,\
        in records(res_file):

        data[scenario][protocol]['total'] = total_bytes
        data[scenario][protocol]['app'] = app_total
        data[scenario][protocol]['padding'] = padding_total
        data[scenario][protocol]['header'] = header_total
        data[scenario][protocol]['handshake'] = handshake_total
        data[scenario][protocol]['mac'] = mac_total

        scenarios.append(scenario)

    return scenarios


def main():
    ## LOAD DATA
    # scenario -> protocol -> data type -> value
    data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

    scenarios = load_data(data, SPP_FILE, 'spp')
    load_data(data, SSL_FILE, 'ssl')
    load_data(data, FWD_FILE, 'fwd')

    #scenarios = data.keys()
    protocols = data[scenarios[0]].keys()
    byte_types = ('app', 'header', 'padding', 'handshake', 'mac')



    ## PLOT

    ##
    ## PLOT 1: total bytes
    ##
    xs = []
    ys = []
    labels = []

    for protocol in protocols:
        xs.append(scenarios)
        vals = []
        for scenario in scenarios:
            vals.append(data[scenario][protocol]['total'])
        ys.append(vals)
        labels.append(protocol)

    myplot.bar(xs, ys, labels=labels, xtick_label_rotation=0,\
        xtick_label_horizontal_alignment='center', ylabel='Total Data Transmitted (kB)',\
        filename='./fig/bytes_total.pdf')
    
    
    ##
    ## PLOT 2: breakdown (header, handshake, app, ...)
    ##
    xs = []
    ys = []  # array of arrays of arrays: each protocol has an array containing arrays for byte types
    labels = []

    for protocol in protocols:
        xs.append(scenarios)
        val_arrays = []  # one per byte type
        for byte_type in byte_types:
            vals = []
            for scenario in scenarios:
                vals.append(data[scenario][protocol][byte_type])
            val_arrays.append(vals)
        ys.append(val_arrays)
        labels.append(protocol)

    myplot.stackbar(xs, ys, labels=labels, xtick_label_rotation=0,\
        xtick_label_horizontal_alignment='center', ylabel='Data Transmitted (kB)',\
        stackbar_pattern_labels=byte_types,\
        width_scale=1.1, grid='y',\
        filename='./fig/bytes_breakdown.pdf')


            

    

if __name__ == '__main__':
    main()

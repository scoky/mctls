#!/usr/bin/env python

import sys
import pprint
from collections import defaultdict
import numpy

import plot
OPT = 60



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



def print_proto_stats(stats, data_key):
    for protocol in stats:
        string = protocol
        string += '\tMin: %f\tMean: %f\tMedian: %f\tMax: %f' % (\
            numpy.min(stats[protocol][data_key]),
            numpy.mean(stats[protocol][data_key]),
            numpy.median(stats[protocol][data_key]),
            numpy.max(stats[protocol][data_key]))
        print string
    

def analyze_browser_bytes(machine, remote, result_files):

    # proto ->
    #   'mac-total' -> list of MAC size sums
    #   'mac-frac-of-app' -> list of MAC overhead fractions
    stats = defaultdict(lambda: defaultdict(list))

    for protocol, result_file in result_files.iteritems():
        for _, total_bytes, app_total, padding_total, header_total,\
            handshake_total, mac_total, alert_total in records(result_file):

            stats[protocol]['mac-total'].append(mac_total)
            stats[protocol]['mac-frac-of-app'].append(mac_total/float(app_total))
            

    
    print 'MAC total (kB):'
    print_proto_stats(stats, 'mac-total')

    print '\nMAC as fraction of app:'
    print_proto_stats(stats, 'mac-frac-of-app')

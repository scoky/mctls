#!/usr/bin/env python

import os
import sys
import argparse
import glob
import re
import pprint
from collections import defaultdict
import numpy

sys.path.append('./myplot')
import myplot
import plot_byte_overhead

# configuration
FIG_DIR = './fig/myplot'
RESULT_DIR = '.'
PROTOCOLS = ('spp', 'spp_mod', 'ssl', 'fwd', 'pln')
LEGEND_STRINGS = {
    'pln': 'No Encryption',
    'fwd': 'Blind Proxy',
    'ssl': 'MITM Proxy',
    'spp': 'TMP',
    'spp_mod': 'TMP (Nagle off)',
}
EXPERIMENT_NAMES = {
    2: 'timeFirstByte_slice',
    3: 'timeFirstByte_latency',
    4: 'timeFirstByte_proxy',
    5: 'downloadTime',
    6: 'downloadTime_browser',
    7: 'connections_slice',
    8: 'byteOverhead_scenarios',
}
#SUFFIXES = {
#    2: {0: 'timeFirstByte_slice', 1: 'remote_timeFirstByte_slice'},
#    3: {0: 'timeFirstByte_latency', 1: 'remote_timeFirstByte_latency'},
#    4: {0: 'timeFirstByte_proxy', 1: 'remote_timeFirstByte_proxy'},
#    5: {0: 'downloadTime', 1: 'remote_downloadTime'},
#    6: {0: 'downloadTime_browser', 1: 'remote_downloadTime_browser'},
#    7: {0: 'connections_slice', 1: 'remote_connections_slice'},
#}
#PLOT_FILENAME = {
#    2: {0: 'time_1st_byte_slice.pdf', 1: 'time_1st_byte_slice_remote.pdf'},
#    3: {0: 'time_1st_byte_latency.pdf', 1: 'time_1st_byte_latency_remote.pdf'},
#    4: {0: 'time_1st_byte_proxy.pdf', 1: 'time_1st_byte_proxy_remote.pdf'},
#    5: {0: 'download_time_fSize.pdf', 1: 'download_time_fSize_remote.pdf'},
#    6: {0: 'download_time_browser-like.pdf', 1: 'download_time_browser-like_remote.pdf'},
#    7: {0: 'connection_per_second.pdf', 1: 'connection_per_second_remote.pdf'},
#}
X_AXIS = {
    2: 'Number of Slices',
    3: 'Link Latency (ms)',
    4: 'Number of Middleboxes',
    5: 'File Size (kB)',
    6: 'Download Time (ms)',
    7: 'Number of Slices',
}
Y_AXIS = {
    2: 'Time to First Byte (ms)',
    3: 'Time to First Byte (ms)',
    4: 'Time to First Byte (ms)',
    5: 'Download Time (s)',
    6: 'CDF',
    7: 'Connections per Second',
    8: 'Data Transmitted (kB)',
}
DATA_TRANSFORMS = {
    2: lambda x: x*1000,
    3: lambda x: x*1000,
    4: lambda x: x*1000,
    5: lambda x: x,
    6: lambda x: x,
    7: lambda x: x,
    8: lambda x: float(x)/1024.,
}
SHOW_RTTS = {
    2: 3,
    3: 3,
    4: 3,
    5: 3,
    6: 0,
    7: 0,
    8: 0,
}

##
## Manually tweak per-plot settings
##
MANUAL_ARGS=defaultdict(dict)
MANUAL_ARGS['connections_slice_local_tid.system-ns.net.pdf'] = {
    'ylim':(0, 500),
}


# returns 3 arrays: rtts, num_mboxes, num_slices
def get_params(opt, remote, data):
    rtts = []
    num_mboxes = []
    num_slices = []

    if opt == 2:
        num_slices = data[:, 0]
        num_mboxes = data[:, 2]
        if remote:
            rtts = data[:, 5]
        else:
            rtts = 2*numpy.multiply(data[:, 1], data[:, 2]+1)

    elif opt == 3:
        num_slices = data[:, 1]
        num_mboxes = data[:, 2]
        rtts = 2*numpy.multiply(data[:, 0], data[:, 2]+1)
        if remote:
            print 'WARNING: shouldn\'t get here'

    elif opt == 4:
        num_mboxes = data[:, 0]
        num_slices = data[:, 1]
        if remote:
            rtts = data[:, 5]
        else:
            rtts = 2*numpy.multiply(data[:, 0]+1, data[:, 2])

    elif opt == 5:
        num_slice = data[:, 1]
        num_mboxes = [1]*data.shape[0]
        if remote:
            print 'WARNING: don\'t know what to do here'
        else:
            rtts = 2*numpy.multiply(data[:, 2], numpy.array(num_mboxes)+1)/1000

    elif opt == 6:
        num_slice = data[1, 2]
        rtt = data[1, 3]

    elif opt == 7:
        num_slices = data[:, 0]
        num_mboxes = data[:, 2]
        if remote and data.shape[1] >= 6:
            rtts = data[:, 5]
        else:
            rtts = 2*numpy.multiply(data[:, 1], data[:, 2]+1)

    return rtts, num_mboxes, num_slices


def title(opt, remote, data):
    title = ''
    if opt == 2 or opt == 7:
        rtt = data[1, 2]
        N = data[1, 3]  # TODO: off by one?
        if not remote:
            title += 'LinkLatency=%d ms   NumMbox=%d' % (rtt, N)
        else:
            title += 'NumMbox=%d' % N

    elif opt == 3:
        num_slice = data[1, 2]
        N = data[1, 3]
        title += 'NumSlice=%d   NumMbox=%d' % (num_slice, N)

    elif opt == 4:
        num_slice = data[1, 2]
        rtt = data[1, 3]
        title += 'NumSlice=%d   LinkLatency=%d ms' % (num_slice, rtt)

    elif opt == 5:
        num_slice = data[1, 2]
        rtt = data[1, 3]
        title += 'NumSlice=%d   LinkLatency=%d ms   Rate=5Mbps' % (num_slice, rtt)

    elif opt == 6:
        num_slice = data[1, 2]
        rtt = data[1, 3]
        if not remote:
            title += 'NumSlice=%d   LinkLatency=%d ms' % (num_slice, rtt)
        else:
            title += 'NumSlice=%d   ' % num_slice

    if remote:
        title += '   AMAZON'
    else:
        title += '   LOCAL'

    return title


def outfile(opt, remote, machine):
    remote_str = 'remote' if remote else 'local'
    machine_str = machine if machine else 'local'
    filename = '%s_%s_%s.pdf' % (EXPERIMENT_NAMES[opt], remote_str, machine_str)
    filepath = os.path.join(FIG_DIR, filename)
    return filename, filepath


def make_rtt_lines(endpoints, num=3):
    # TODO: use num
    lines = []
    for i in range(1, num+1):
        line = {
            'endpoints':((endpoints[0][0], endpoints[0][1]*i),
                         (endpoints[1][0], endpoints[1][1]*i)),
            'stretch':True,
            'line_args':{
                'linewidth':1,
                'color':'gray',
                'alpha':0.5,
            },

            'label':'%d RTT' % i,
            'label_args':{
                'color':'gray',
                'alpha':0.5,
                'size':'x-small',
            },
        }
        lines.append(line)
    return lines







# result_files is a dict: protocol -> result file path
def plot_series(machine, remote, result_files):

    out_filename, out_filepath = outfile(args.opt, remote, machine)

    xs = []  # holds arrays of x values, 1 per series
    ys = []  # holds arrays of y values, 1 per series
    yerrs = []  # holds arrays of std devs, 1 per series
    labels = []
    plot_title = ''

    # maps X value (e.g., num slices or num mboxes) to a list of measured or
    # calculated RTTs for that value (sometimes RTT depends on X, e.g., #mbox)
    x_to_rtts = defaultdict(list)

    for protocol in PROTOCOLS:
        if protocol not in result_files: continue
        filepath = result_files[protocol]
        print '[IN]', protocol, filepath
        data = numpy.loadtxt(filepath)
        if len(data) == 0 or\
           len(data.shape) != 2 or\
           data.shape[1] not in (5, 7):  # should be either 5 or 7 cols
            print 'WARNING: malformed data: %s' % filepath
            continue

        transform = numpy.vectorize(DATA_TRANSFORMS[args.opt])
        
        xs.append(data[:,0])
        ys.append(transform(data[:,3]))
        yerrs.append(transform(data[:,4]))
        labels.append(LEGEND_STRINGS[protocol])
        plot_title = title(args.opt, remote, data)

        # RTT measurements
        rtts, _, _ = get_params(args.opt, remote, data)
        for i in range(data.shape[0]):
            x_to_rtts[data[i,0]].append(rtts[i])

    rtt_lines = []
    if SHOW_RTTS[args.opt]:
        # average RTT measurements
        for x in x_to_rtts:
            x_to_rtts[x] = numpy.mean(x_to_rtts[x])
        # find RTT line endpoints
        e1 = (xs[0][0], x_to_rtts[xs[0][0]])
        e2 = (xs[0][-1], x_to_rtts[xs[0][-1]])
        rtt_lines = make_rtt_lines((e1, e2), SHOW_RTTS[args.opt])
            

    # TODO: avg RTT measurment
    rtt = 75

    if len(xs) != len(ys) or len(ys) != len(yerrs) or\
       len(yerrs) != len(labels) or len(ys) == 0:
        print 'ERROR: no well-formed data to plot ***'
        return

    print '[OUT]', out_filepath
    myplot.plot(xs, ys, yerrs=yerrs, labels=labels, xlabel=X_AXIS[args.opt],\
        ylabel=Y_AXIS[args.opt], guide_lines=rtt_lines,\
        #title=plot_title,\
        filename=out_filepath, **MANUAL_ARGS[out_filename])



def main():

    # Discover result files for this experiment type. Result files may be
    # available some subset of the protocols, remote or local, and from different
    # machines.

    # machine name -> protocol -> result file path
    remote_files = defaultdict(lambda:defaultdict(list))  
    local_files = defaultdict(lambda:defaultdict(list))
    for result_file in glob.glob(RESULT_DIR + '/*%s*' % EXPERIMENT_NAMES[args.opt]):
        m = re.match(r'.*res_(.{3}|spp_mod)_(remote_)?%s(_(.*))?' % EXPERIMENT_NAMES[args.opt], result_file)
        if m:
            protocol = m.group(1)
            remote = (m.group(2) is not None)
            remainder = m.group(4)
            machine = None

            if remainder:  # decide if it's garbage or machine name
                if remainder == 'tid.system-ns.net' or \
                   remainder == 'localhost' or \
                   re.match('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', remainder):
                    machine = remainder
                else:
                    print 'WARNING: unexpeted file name: %s' % result_file
                    continue

            if remote:
                remote_files[machine][protocol] = result_file
            else:
                local_files[machine][protocol] = result_file

        else:
            print 'WARNING: unexpeted file name: %s' % result_file
            continue

    if args.opt in (1, 2, 3, 4, 5, 7):
        for machine, result_files in remote_files.iteritems():
            plot_series(machine, True, result_files)

        for machine, result_files in local_files.iteritems():
            plot_series(machine, False, result_files)

    elif args.opt in (8,):
        for machine, result_files in remote_files.iteritems():
            plot_byte_overhead.plot_byte_scenarios(machine, True, result_files)

        for machine, result_files in local_files.iteritems():
            plot_byte_overhead.plot_byte_scenarios(machine, False, result_files)
        

    # TODO: CDF for opt 6

    

    

if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Manage all the stages of site crawling for HTTPS Dashboard.')
    parser.add_argument('opt', type=int, help='Experiment type')
    args = parser.parse_args()

    main()

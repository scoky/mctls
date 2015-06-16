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
import plot_time_scenarios
import browser_byte_overhead

# configuration
FIG_DIR = './fig/myplot'
RESULT_DIR = './final'
PROTOCOLS = {
    2: ('spp', 'ssl', 'fwd', 'pln', 'spp_mod'),
    3: ('spp', 'ssl', 'fwd', 'pln', 'spp_mod'),
    4: ('spp', 'ssl', 'fwd', 'pln', 'spp_mod'),
    5: ('spp', 'ssl', 'fwd', 'pln', 'spp_mod'),
    6: ('spp', 'ssl', 'fwd', 'pln', 'spp_mod'),
    7: ('spp', 'ssl', 'fwd', 'spp_mod', 'spp_2', 'spp_4'),
    8: ('spp', 'ssl', 'fwd', 'pln'),
    9: ('spp', 'ssl', 'fwd', 'pln', 'spp_mod'),
}
LEGEND_STRINGS = {
    'pln': 'NoEncrypt',
    'fwd': 'E2E-TLS',
    'ssl': 'SplitTLS',
    'spp': 'mcTLS',
    'spp_mod': 'mcTLS (Nagle off)',
    'ssl_mod': 'SplitTLS (Nagle off)',
    'fwd_mod': 'E2E-TLS (Nagle off)',
    'pln_mod': 'NoEncrypt (Nagle off)',
    'spp_2': 'mcTLS (2 mbox)',
    'spp_4': 'mcTLS (4 mbox)',
}
EXPERIMENT_NAMES = {
    2: 'timeFirstByte_slice',
    3: 'timeFirstByte_latency',
    4: 'timeFirstByte_proxy',
    5: 'downloadTime',
    6: 'page_load_time',
    7: 'connections_slice',
    8: 'byteOverhead_scenarios',
    9: 'timeFirstByte_scenarios',
    60: 'byteOverhead_browser',
}
X_AXIS = {
    2: 'Number of Contexts',
    3: 'Link Latency (ms)',
    4: 'Number of Middleboxes',
    5: 'File Size (kB)',
    6: 'Load Time (s)',
    7: 'Number of Contexts',
}
Y_AXIS = {
    2: 'Time to First Byte (ms)',
    3: 'Time to First Byte (ms)',
    4: 'Time to First Byte (ms)',
    5: 'Download Time (s)',
    6: 'CDF',
    7: 'Connections per Second',
    8: 'Size (kB)',
    9: 'Download Time (s)',
}
DATA_TRANSFORMS = {
    2: lambda x: x*1000,
    3: lambda x: x*1000,
    4: lambda x: x*1000,
    5: lambda x: x,
    6: lambda x: x,
    7: lambda x: x,
    8: lambda x: float(x)/1024.,
    9: lambda x: float(x),
    60: lambda x: float(x)/1024.,
}
SHOW_RTTS = {
    2: 4,
    3: 4,
    4: 4,
    5: 3,
    6: 0,
    7: 0,
    8: 0,
    9: 4,
}

##
## Manually tweak per-plot settings
##
MANUAL_ARGS=defaultdict(dict)
MANUAL_ARGS['connections_slice_local_tid.system-ns.net.pdf'] = {
    'ylim':(0, 500),
}
MANUAL_ARGS['timeFirstByte_slice_local_local.pdf'] = {
    'legend_loc': 'upper left',
    'xlim': (0, 16),
}
MANUAL_ARGS['page_load_time_local_local_slicing-comparison.pdf'] = {
    'xlim':(0, 12),
}
MANUAL_ARGS['page_load_time_remote_local_slicing-comparison.pdf'] = {
    'legend_text_size':17,
}
MANUAL_ARGS['page_load_time_local_local_proto-comparison.pdf'] = {
    'xlim':(0, 12),
}
MANUAL_ARGS['page_load_time_remote_local_proto-comparison.pdf'] = {
    'xlim':(0, 30),
}
MANUAL_ARGS['timeFirstByte_scenarios_local_local.pdf'] = {
    'width_scale':3,
    'yscale':'log',
}
MANUAL_ARGS['connections_slice_local_server_54-67-37-251.pdf'] = {
    'ylim':(0, 600),
}
MANUAL_ARGS['connections_slice_local_server_54-76-148-166.pdf'] = {
    'ylim':(0, 600),
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
        num_slice = data[1, 1]
        rtt = data[1, 0]
        if not remote:
            title += 'NumSlice=%d   LinkLatency=%d ms' % (num_slice, rtt)
        else:
            title += 'NumSlice=%d   ' % num_slice

    if remote:
        title += '   AMAZON'
    else:
        title += '   LOCAL'

    return title


def outfile(opt, remote, machine, extra_tag=''):
    remote_str = 'remote' if remote else 'local'
    machine_str = machine if machine else 'local'
    filename = '%s_%s_%s%s.pdf' % (EXPERIMENT_NAMES[opt], remote_str, machine_str, extra_tag)
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
                'alpha':0.7,
            },

            'label':'%d RTT' % i,
            'label_args':{
                'color':'gray',
                'alpha':0.7,
                'size':'small',
            },
        }
        lines.append(line)
    return lines


#def dump_to_file_for_xkcd(xs, ys, labels, filepath):
#    filepath += '.tsv'
#    with open(filepath, 'w') as f:
#        header_str = ''
#        for label in labels:
#            header_str += '%s_X\t%s\t' % (label, label)
#        f.write('%s\n' % header_str)
#        
#        # FIXME: assumes all series have same num points
#        for point in range(len(xs[0])):
#            line = ''
#            for series in range(len(xs)):
#                line += '%s\t%s\t' % (xs[series][point], ys[series][point])
#            f.write('%s\n' % line)

def dump_to_file_for_xkcd(xs, ys, yerrs, labels, filepath):
    filepath += '.tsv'
    with open(filepath, 'w') as f:
        f.write('protocol\tX\tY\tstddev\n')
        
        for series in range(len(xs)):
            line = ''
            for point in range(len(xs[0])):
                line += '%s\t%d\t%f\t%f\n' % (labels[series], xs[series][point], ys[series][point], yerrs[series][point])
            f.write(line)
                







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

    for protocol in PROTOCOLS[args.opt]:
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
        ylabel=Y_AXIS[args.opt], guide_lines=rtt_lines[1:],\
        #title=plot_title,\
        filename=out_filepath, **MANUAL_ARGS[out_filename])

    dump_to_file_for_xkcd(xs, ys, yerrs, labels, out_filepath)
            

# result_files is a dict: protocol -> result file path
def plot_browser(machine, remote, result_files):

    ##
    ## plot 1: compare 4-slice version of all protocols
    ##
    out_filename, out_filepath = outfile(args.opt, remote, machine,\
        extra_tag='_proto-comparison')

    # need to make alternate dict of result paths
    temp_result_files = {}
    if 'spp_four-slices' in result_files:
        temp_result_files['spp'] = result_files['spp_four-slices']
    if 'spp_mod_four-slices' in result_files:
        temp_result_files['spp_mod'] = result_files['spp_mod_four-slices']
    if 'ssl_four-slices' in result_files:
        temp_result_files['ssl'] = result_files['ssl_four-slices']
    if 'ssl_mod_four-slices' in result_files:
        temp_result_files['ssl_mod'] = result_files['ssl_mod_four-slices']
    if 'fwd_four-slices' in result_files:
        temp_result_files['fwd'] = result_files['fwd_four-slices']
    if 'fwd_mod_four-slices' in result_files:
        temp_result_files['fwd_mod'] = result_files['fwd_mod_four-slices']
    if 'pln_four-slices' in result_files:
        temp_result_files['pln'] = result_files['pln_four-slices']
    if 'pln_mod_four-slices' in result_files:
        temp_result_files['pln_mod'] = result_files['pln_mod_four-slices']
        
    ys = []  # holds arrays of y values, 1 per series
    labels = []
    plot_title = ''

    for protocol in PROTOCOLS[args.opt]:
        if protocol not in temp_result_files: continue
        filepath = temp_result_files[protocol]
        print '[IN]', protocol, filepath
        data = numpy.loadtxt(filepath)
        if len(data) == 0 or\
           len(data.shape) != 2 or\
           data.shape[1] != 3:
            print 'WARNING: malformed data: %s' % filepath
            continue
        
        transform = numpy.vectorize(DATA_TRANSFORMS[args.opt])

        print protocol, max(transform(data[:,2]))
        ys.append(transform(data[:,2]))
        if protocol == 'spp':
            labels.append(LEGEND_STRINGS[protocol] + ' (4 Ctx)')
        elif protocol == 'spp_mod':
            labels.append('mcTLS (4 Ctx, Nagle Off)')
        else:
            labels.append(LEGEND_STRINGS[protocol])
        plot_title = title(args.opt, remote, data)

    print '[OUT]', out_filepath
    myplot.cdf(ys, labels=labels, xlabel=X_AXIS[args.opt],\
        #title=plot_title,\
        filename=out_filepath, **MANUAL_ARGS[out_filename])
    
    
    ##
    ## plot 2: compare slice strategies (SPP only)
    ##
    out_filename, out_filepath = outfile(args.opt, remote, machine,\
        extra_tag='_slicing-comparison')

    ys = []  # holds arrays of y values, 1 per series
    labels = []
    plot_title = ''

    SLICE_LEGEND = {
        'spp_one-slice': 'mcTLS (1 Ctx)',
        'spp_mod_one-slice': 'mcTLS (1 Ctx, Nagle Off)',
        'spp_four-slices': 'mcTLS (4 Ctx)',
        'spp_mod_four-slices': 'mcTLS (4 Ctx, Nagle Off)',
        'spp_slice-per-header': 'mcTLS (Ctx per Hdr)',
        'spp_mod_slice-per-header': 'mcTLS (Ctx per Hdr, Nagle Off)',
    }

    for protocol in ('spp_one-slice', 'spp_mod_one-slice', 'spp_four-slices', 'spp_mod_four-slices', 'spp_slice-per-header', 'spp_mod_slice-per-header'):
        if protocol not in result_files: continue
        filepath = result_files[protocol]
        print '[IN]', protocol, filepath
        data = numpy.loadtxt(filepath)
        if len(data) == 0 or\
           len(data.shape) != 2 or\
           data.shape[1] != 3:
            print 'WARNING: malformed data: %s' % filepath
            continue
        
        transform = numpy.vectorize(DATA_TRANSFORMS[args.opt])

        ys.append(transform(data[:,2]))
        labels.append(SLICE_LEGEND[protocol])
        plot_title = title(args.opt, remote, data)

    print '[OUT]', out_filepath
    myplot.cdf(ys, labels=labels, xlabel=X_AXIS[args.opt],\
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
        m = re.match(r'.*res_((.{3}(_mod)?)(_one-slice|_four-slices|_slice-per-header|_[0-9])?)_(remote_)?%s(_(.*))?' %\
            EXPERIMENT_NAMES[args.opt], result_file)
        if m:
            protocol = m.group(1)
            remote = (m.group(5) is not None)
            remainder = m.group(7)
            machine = None

            if remainder:  # decide if it's garbage or machine name
                if re.match('(server|mbox|client)?_tid.system-ns.net', remainder) or \
                   re.match('(server|mbox|client)?_localhost', remainder) or \
                   re.match('(server|mbox|client)?_[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', remainder):
                    machine = remainder
                    machine = machine.replace('.', '-')

                    
                else:
                    print 'WARNING: unexpected file name: %s' % result_file
                    continue

            if remote:
                remote_files[machine][protocol] = result_file
            else:
                local_files[machine][protocol] = result_file

        else:
            print 'WARNING: unexpected file name: %s' % result_file
            continue

    if args.opt in (1, 2, 3, 4, 5, 7):
        for machine, result_files in remote_files.iteritems():
            plot_series(machine, True, result_files)

        for machine, result_files in local_files.iteritems():
            plot_series(machine, False, result_files)

    elif args.opt == 6:
        for machine, result_files in remote_files.iteritems():
            plot_browser(machine, True, result_files)

        for machine, result_files in local_files.iteritems():
            plot_browser(machine, False, result_files)

    elif args.opt in (8,):
        for machine, result_files in remote_files.iteritems():
            plot_byte_overhead.plot_byte_scenarios(machine, True, result_files)

        for machine, result_files in local_files.iteritems():
            plot_byte_overhead.plot_byte_scenarios(machine, False, result_files)

    elif args.opt == 9:
        for machine, result_files in remote_files.iteritems():
            plot_time_scenarios.plot_time_scenarios(machine, True, result_files)

        for machine, result_files in local_files.iteritems():
            plot_time_scenarios.plot_time_scenarios(machine, False, result_files)

    elif args.opt == 60:
        for machine, result_files in remote_files.iteritems():
            browser_byte_overhead.analyze_browser_bytes(machine, True, result_files)

        for machine, result_files in local_files.iteritems():
            browser_byte_overhead.analyze_browser_bytes(machine, False, result_files)
        
        
    

    

if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Plot mcTLS experiment results.')
    parser.add_argument('opt', type=int, help='Experiment type')
    args = parser.parse_args()

    main()

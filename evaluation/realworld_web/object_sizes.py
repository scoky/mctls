#! /usr/bin/env python

import sys
import os
import logging
import argparse
import glob
import datetime
from collections import defaultdict
import numpy

sys.path.append('./web-profiler')
from webloader.har import Har, HarError

sys.path.append('../results/myplot')
import myplot


def main():
    if len(args.hars) == 1 and os.path.isdir(args.hars[0]):
        harpaths = glob.glob(args.hars[0] + '/*.har')
    else:
        harpaths = args.hars
        
        
    sizes = []
    num_zeros = 0
    for harpath in harpaths:
        # load HAR
        try:
            har = Har.from_file(harpath)
            logging.info(har)
        except HarError:
            logging.exception('Error parsing HAR')
            continue

        # store object sizes in array
        for obj in har.objects:
            sizes.append(obj.size)
            if obj.size == 0:
                num_zeros += 1

    print num_zeros, 'zeros'
    print 'Mean:\t\t%f B' % numpy.mean(sizes)
    print 'Min: ', numpy.min(sizes)
    for percentile in (1, 10, 25, 50, 75, 90, 99):
        print '%dth percentile:\t%f B' % (percentile,\
            numpy.percentile(sizes, percentile))
    print 'Max: ', numpy.max(sizes)

    myplot.cdf([numpy.array(sizes)/1024.0], xlabel='Object Size (kB)',\
        title='Object Sizes in Alexa Top 500', filename='./object_size_cdf.pdf')
    
    myplot.cdf([sizes], xlabel='Object Size (kB)', xscale='log',\
        title='Object Sizes in Alexa Top 500', filename='./object_size_cdf_log.pdf')


if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(description='Extract object request timings from a HAR file.')
    parser.add_argument('hars', nargs='+', help='HAR files (or directory of HARs) to analyze')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help='only print errors')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print debug info. --quiet wins if both are present')
    args = parser.parse_args()
    
    # set up logging
    if args.quiet:
        level = logging.WARNING
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno) -7s %(message)s",
        level = level
    )

    main()

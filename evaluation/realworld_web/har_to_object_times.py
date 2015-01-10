#! /usr/bin/env python

import sys
import os
import logging
import argparse

sys.path.append('./web-profiler')
from webloader.har import Har, HarError



def main():
    # load HAR
    try:
        har = Har.from_file(args.har)
    except HarError:
        logging.exception('Error parsing HAR')

    # write CSV list of objects along with time offset from beginning.
    out_path = os.path.splitext(args.har)[0] + '.tab'
    with open(out_path, 'w') as f:
        f.write('host\t path\tcompressed size (bytes)\toriginal size (bytes)\trequest start offset (sec)\t new TCP connection?\t new SSL handshake?\t original URL\n\n')
        for obj in har.objects:
            f.write('%s\t%s\t%d\t%d\t%f\t%s\t%s\t%s\n' %\
                (obj.host,\
                obj.path,\
                obj.size,\
                obj.content_size,\
                (obj.object_start_time - har.page_start_time).total_seconds(),\
                obj.tcp_handshake,\
                obj.ssl_handshake,\
                obj.url))


if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(description='Extract object request timings from a HAR file.')
    parser.add_argument('har', help='HAR file to analyze')
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

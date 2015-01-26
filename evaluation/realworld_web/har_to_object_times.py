#! /usr/bin/env python

import sys
import os
import logging
import argparse
import glob
import datetime
import random
from collections import defaultdict

sys.path.append('./web-profiler')
from webloader.har import Har, HarError

# How much data should go in each slice if there is only one slice
def slice_sizes_one_slice(obj, dummy1, dummy2):
    request_size = obj.request_headers_size + max(obj.request_body_size, 0)
    response_size = obj.response_headers_size + obj.response_body_size
    return request_size, response_size

# How much data should go in each slice if there's one slice each for (1) req
# headers, (2) req body, (3) resp headers, (4) resp body
def slice_sizes_headers_content(obj, dummy1, dummy2):
    request_sizes = '%d;%d;0;0' % (obj.request_headers_size,\
        max(obj.request_body_size, 0))
    response_sizes = '0;0;%d;%d' % (obj.response_headers_size, obj.response_body_size)
    return request_sizes, response_sizes
    

# How much data should go in each slice if each HTTP header gets its own slice?
def slice_sizes_slice_per_header(obj, num_req_slices, num_resp_slices):
    total_slices = num_req_slices + num_resp_slices + 1  # +1 for GET
    # get request header sizes
    request_sizes = ''
    total_req_hdr_size = 2  # final \n\r
    for header, value in obj.request_headers.iteritems():
        req_hdr_size = len(header) + len(value) + 4  # : \n\r
        total_req_hdr_size += req_hdr_size
        request_sizes += ';%d' % req_hdr_size
    # NOTE: we're losing the 2 byte \n\r following the last header

    # add the size of the request line (GET ... )
    request_sizes = '%d%s' % (obj.request_headers_size - total_req_hdr_size,\
        request_sizes)

    # add content size
    request_sizes += ';%d' % max(obj.request_body_size, 0)

    # pad with 0's for extra request slices + response slices
    request_sizes += ';0' * (total_slices - len(obj.request_headers))



    
    # get response header sizes
    response_sizes = ''
    total_resp_hdr_size = 2  # final \n\r
    for header, value in obj.response_headers.iteritems():
        resp_hdr_size = len(header) + len(value) + 4  # : \n\r
        total_resp_hdr_size += resp_hdr_size
        response_sizes += ';%d' % resp_hdr_size
    # NOTE: we're losing the 2 byte \n\r following the last header

    # add the size of the response line (GET ... )
    response_sizes = '%d%s' % (obj.response_headers_size - total_resp_hdr_size,\
        response_sizes)

    # add content size
    response_sizes += ';%d' % max(obj.response_body_size, 0)

    # pad with 0's for extra response slices + request slices
    response_sizes = '0;' *\
        (total_slices - len(obj.response_headers))\
        + response_sizes

    # make sure we have the right number of slices in each column
    if len(request_sizes.split(';')) != len(response_sizes.split(';')):
        print 'WRONG', len(request_sizes.split(';')), len(response_sizes.split(';'))

    
    return request_sizes, response_sizes




def save_action_list_for_har(har_path, slice_sizes_func, slice_tag):
    # load HAR
    try:
        har = Har.from_file(har_path)
        logging.info(har)
    except HarError:
        logging.exception('Error parsing HAR')
        return


    # make sure the first response is a 200 OK
    if har.objects[0].response_code != 200:
        logging.warn('Not 200 OK; skipping. %s' % har)
        return


    # count the max # HTTP request and response headers in any request
    # (so we know how many slices we need for slice-per-header scenario)
    num_req_slices = 0
    num_resp_slices = 0
    for obj in har.objects:
        num_req_slices = max(num_req_slices, len(obj.request_headers))
        num_resp_slices = max(num_resp_slices, len(obj.response_headers))

    
    # FILE 1:
    # write a simpler "action list" for Matteo's client
    # fields:
    # time size assigned_conn
    action_path = os.path.splitext(har_path)[0] + '.%s.actions' % slice_tag
    with open(action_path, 'w') as actionf:
    
    
        # FILE 2:
        # write CSV list of objects along with time offset from beginning.
        out_path = os.path.splitext(har_path)[0] + '.%s.csv' % slice_tag
        with open(out_path, 'w') as detailsf:
            detailsf.write('host,compressed size (bytes),original size (bytes),request slice bytes,response slice bytes,request start offset (sec),new TCP connection?,new SSL handshake?,new conn?,#conn so far,assigned conn,path,original URL\n\n')


            # LOOP OVER OBJECTS
            last_timestamp = None
            servers_so_far = set()  # track which servers this page has loaded from
            server_to_num_conn = defaultdict(int)
            for obj in har.objects:
                # did chrome open a new connection for this object?
                new_connection = obj.tcp_handshake\
                    or obj.ssl_handshake\
                    or obj.host not in servers_so_far

                # is this a new connection for this server? 
                assigned_connection = -1
                if new_connection:
                    # if so, add to count
                    server_to_num_conn[obj.host] += 1
                    assigned_connection = server_to_num_conn[obj.host] - 1
                else:
                    # if not, assign to random open connection
                    assigned_connection = random.randint(0,\
                        server_to_num_conn[obj.host] - 1)

                # how much data should go in each slice for req and resp?
                request_slice_sizes, response_slice_sizes =\
                    slice_sizes_func(obj, num_req_slices, num_resp_slices)


                # FILE 1  (actions)
                actionf.write('%f %s %s %d\n' %\
                    ((obj.object_start_time - har.page_start_time).total_seconds(),\
                    request_slice_sizes,\
                    response_slice_sizes,\
                    assigned_connection))

                # FILE 2  (details)
                detailsf.write('%s,%d,%d,%s,%s,%f,%s,%s,%s,%d,%d,%s,%s\n' %\
                    (obj.host,\
                    obj.size,\
                    obj.content_size,\
                    request_slice_sizes,\
                    response_slice_sizes,\
                    (obj.object_start_time - har.page_start_time).total_seconds(),\
                    obj.tcp_handshake,\
                    obj.ssl_handshake,\
                    new_connection,\
                    server_to_num_conn[obj.host],\
                    assigned_connection,
                    obj.path,\
                    obj.url))

                last_timestamp = obj.object_start_time
                servers_so_far.add(obj.host)

            actionf.write('%f -1 -1\n' %\
                (last_timestamp - har.page_start_time + datetime.timedelta(0, 5))\
                .total_seconds())


def main():
    if len(args.hars) == 1 and os.path.isdir(args.hars[0]):
        harpaths = glob.glob(args.hars[0] + '/*.har')
    else:
        harpaths = args.hars

    for harpath in harpaths:
        save_action_list_for_har(harpath, slice_sizes_one_slice, 'one-slice')
        save_action_list_for_har(harpath, slice_sizes_headers_content, 'four-slices')
        save_action_list_for_har(harpath, slice_sizes_slice_per_header, 'slice-per-header')


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

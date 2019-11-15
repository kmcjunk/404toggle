#!/usr/bin/env python3
# Copyright 2019 Kevin McJunkin
# License: Apache

import concurrent.futures
import logging
import queue
import threading
import requests
import argparse
import json


# Auth class
class KAuth:
    def __init__(self, username, apikey):
        self.username = username
        self.apikey = apikey

    def authenticate(self, **kwargs):
        if 'service' in kwargs:
            service = kwargs['service']
        else:
            service = None

        if 'region' in kwargs:
            region = kwargs['region'].upper()
        else:
            region = None

        url = 'https://identity.api.rackspacecloud.com/v2.0'
        endpoint = url + '/tokens'
        headers = {'Content-type': 'Application/json'}
        payload = {
            "auth": {
                "RAX-KSKEY:apiKeyCredentials": {
                    "username": self.username,
                    "apiKey": self.apikey}
                    }
                    }
        try:
            r = requests.post(endpoint,
                              data=json.dumps(payload),
                              headers=headers)
            j = r.json()
            token = j['access']['token']['id']
            if service and region:
                for services in j['access']['serviceCatalog']:
                    if services['name'] == service:
                        service_list = services['endpoints']
                        for data in service_list:
                            if data['region'] == region:
                                service_url = data['publicURL']
                return token, service_url

        except KeyError:
            logging.info('Main: Identity did not return a token',
                         'Exiting.')
            exit(1)

        return token


# Files class
class KFile:
    def __init__(self, token, file_url):
        self.token = token
        self.file_url = file_url

    def disable_container(self, container):
        endpoint = f'{self.file_url}/{container}'
        headers = {'X-Auth-Token': self.token,
                   'X-CDN-ENABLED': 'False'}
        try:
            r = requests.post(endpoint, headers=headers)
            if r.status_code == 201:
                pass
            elif r.status_code == 204:
                pass
            elif r.status_code == 202:
                pass
            else:
                logging.info(f'Consumer: Error Disabling container {container}'
                             ' check 404error.log for details')
        except:
            print(f'Exception on {container}')

    def enable_container(self, container):
        endpoint = f'{self.file_url}/{container}'
        headers = {'X-Auth-Token': self.token,
                   'X-CDN-ENABLED': 'True'}
        try:
            r = requests.put(endpoint, headers=headers)
            if r.status_code == 201:
                pass
            elif r.status_code == 204:
                pass
            elif r.status_code == 202:
                pass
            else:
                logging.info(f'Consumer: Error Enabling container {container}.'
                             f'Status code: {r.status_code}')
                logging.info(r.status_code)
        except:
            print(f'Exception on {container}')


# Doin things
def get_cdn(marker=None):
    headers = {'X-Auth-Token': token}
    endpoint = file_url + '?format=json'
    if marker:
        updated_container_list = []
        endpoint = file_url + '?format=json&marker=' + marker
        r = requests.get(endpoint, headers=headers, stream=True)
        j = r.json()
        if j:
            for container in j:
                updated_container_list.append(container['name'])
                marker = updated_container_list[-1]
            return updated_container_list, marker
        marker = None
        return updated_container_list, marker
    r = requests.get(endpoint, headers=headers, stream=True)
    j = r.json()
    for container in j:
        cdn_container_list.append(container['name'])
    marker = cdn_container_list[-1]
    return cdn_container_list, marker


def check_header(container):
    headers = {'X-Auth-Token': token}
    endpoint = file_url + '/' + container
    r = requests.head(endpoint, headers=headers, stream=True)
    cdn_status = r.headers['X-Cdn-Enabled']
    try:
        if cdn_status == 'True':
            cdn_list.append(container)
            return container
        if cdn_status == 'False':
            bad_list.append(container)
            pass
    except:
        pass


def get_threads():
    thread_list = []
    headers = {'X-Auth-Token': token}
    endpoint = file_url + '?format=json'
    r = requests.get(endpoint, headers=headers, stream=True)
    j = r.json()
    for container in j:
        thread_list.append(container['name'])
    if len(thread_list) >= 100:
        workers = 90
    if len(thread_list) < 100:
        workers = len(thread_list)
    logging.info(f'Main: Spinning up {workers} thread(s)')
    return workers


def do_stuff(cdn_container, queue):
    if cdn_container:
        files.disable_container(cdn_container)
        files.enable_container(cdn_container)
        flipped_list.append(cdn_container)
        logging.info(f'Consumer: (tc={threading.active_count()},'
                     f' queue size={queue.qsize()})'
                     f' Toggling CDN status for {cdn_container}')


"""1st issue
    A) producer/consumer both blocking queue
    B) Attempting to give priority to producer b failin"""
def producer(queue, event):
    """Grab all CDN containers that have ever existed ever"""
    marker = None
    while not event.is_set() or marker != None:
        message, marker = get_cdn(marker=marker)
        logging.info("Producer: got message, number of "
                     "containers added to queue - %s",
                     len(message))
        for i in message:
            queue.put(i, block=False, timeout=150)
        if marker:
            logging.info(f'Producer has marker: {marker}')
            logging.info(f'Producer: Queue size: {queue.qsize()}')
    logging.info("Producer: received event. Exiting")


"""2nd issue, prolly race condition:
    consumers are receiving event() instead of staying alive
    when producer lags behind"""
def consumer(queue, event):
    """Check if they are currently CDN enabled
       via headers. If true: toggle container"""
    while not event.is_set() or not queue.empty():
        message = queue.get(block=True, timeout=20)
        cdn_container = check_header(message)
        do_stuff(cdn_container, queue)


parser = argparse.ArgumentParser(
    description='''disable and renable cdn containers region wide''')
parser.add_argument('-u', '--user', dest='username',
                    help='User on account')
parser.add_argument('-k', '--key', dest='apikey',
                    help='API Key of User')
parser.add_argument('-r', '--region', dest='region',
                    default='ORD',
                    help='Region to mess wit')


if __name__ == "__main__":
    args = parser.parse_args()
    args.region = args.region.upper()
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format,
                        level=logging.INFO,
                        datefmt="%H:%M:%S",
                        handlers=[
                                logging.FileHandler("404toggle.log"),
                                logging.StreamHandler()
                                ]
                        )

    auth = KAuth(args.username, args.apikey)
    token, file_url = auth.authenticate(service='cloudFilesCDN',
                                        region=args.region)
    files = KFile(token, file_url)
    cdn_queue = queue.Queue()
    event = threading.Event()
    cdn_container_list = []
    cdn_list = []
    bad_list = []
    flipped_list = []
    logging.info('Main: Determining number of threads to create')
    n_workers = get_threads()
    "Uncomment line below to set number of workers, yolo"
    # n_workers = 100
    """Start threads"""
    futures = concurrent.futures.ThreadPoolExecutor(max_workers=n_workers + 1)
    with futures as executor:
        executor.submit(producer, cdn_queue, event)
        for n in range(0, n_workers):
            executor.submit(consumer,
                            cdn_queue,
                            event)

        logging.info("Main: about to set event")
        event.set()

    logging.info(f'Main: Total number of enabled containers - {len(cdn_list)}')
    logging.info(f'Main: Total number of disabled container - {len(bad_list)}')
    logging.info(f'Main: Total checked - {len(cdn_list) + len(bad_list)}')
    logging.info(f'Main: Containers toggled - {len(flipped_list)}')

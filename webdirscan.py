#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import Queue
import argparse
import requests
import threading
import IPy
import sys

class Dirscan(object):

    def __init__(self, scanSite, scanDict, scanOutput,threadNum):
        # print 'Dirscan is running!'
        self.scanSite = scanSite if scanSite.find('://') != -1 else 'http://%s' % scanSite
        print 'Scan target:',self.scanSite
        self.scanDict = scanDict
        self.scanOutput = scanSite.rstrip('/').replace('https://', '').replace('http://', '')+'.txt' if scanOutput == 0 else scanOutput
        truncate = open(self.scanOutput,'w')
        truncate.close()
        self.threadNum = threadNum
        self.lock = threading.Lock()
        self._loadHeaders()
        self._loadDict(self.scanDict)
        self._analysis404()
        self.STOP_ME = False

    def _loadDict(self, dict_list):
        self.q = Queue.Queue()
        with open(dict_list) as f:
            for line in f:
                if line[0:1] != '#':
                    self.q.put(line.strip())
        if self.q.qsize() > 0:
            print 'Total Dictionary:',self.q.qsize()
        else:
            print 'Dict is Null ???'
            quit()

    def _loadHeaders(self):
        self.headers = {
            'Accept': '*/*',
            'Referer': 'https://www.baidu.com',
            'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)',
            'Cache-Control': 'no-cache',
        }
    def _analysis404(self):
        notFoundPage = requests.get(self.scanSite + '/trytoanalysis404/trytoanalysis404.html', headers=self.headers, allow_redirects=False)
        self.notFoundPageText = notFoundPage.text.replace('/trytoanalysis404/trytoanalysis404.html', '')

    def _writeOutput(self, result):
        self.lock.acquire()
        with open(self.scanOutput, 'a+') as f:
            f.write(result + '\n')
        self.lock.release()

    def _scan(self, url):
        html_result = 0
        try:
            html_result = requests.get(url, headers=self.headers, allow_redirects=False, timeout=60)
        except requests.exceptions.ConnectionError:
            # print 'Request Timeout:%s' % url
            pass
        finally:
            if html_result != 0:
                if html_result.status_code == 200 and html_result.text != self.notFoundPageText:
                    print '[{0}]{1} ({2} B)'.format(html_result.status_code, html_result.url, len(html_result.content))
                    self._writeOutput('[{0}]{1} ({2} B)'.format(html_result.status_code, html_result.url, len(html_result.content)))

    def run(self):
        while not self.q.empty() and self.STOP_ME == False:
            url = self.scanSite.rstrip('/') + self.q.get()
            self._scan(url)


# 多线程扫描
def begin_scan(scan, thread_num):
    for i in range(thread_num):
        t = threading.Thread(target=scan.run)
        t.setDaemon(True)
        t.start()

    while True:
        if threading.activeCount() <= 1:
            break
        else:
            try:
                time.sleep(0.1)
            except KeyboardInterrupt, e:
                print '\n[WARNING] User aborted, wait all slave threads to exit, current(%i)' % threading.activeCount()
                scan.STOP_ME = True

    print 'Scan end!!!'


def active_host_scan(ip_queue, ip_list):
    lock = threading.Lock()
    headers = {
            'Accept': '*/*',
            'Referer': 'https://www.baidu.com',
            'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)',
            'Cache-Control': 'no-cache',
        }
    
    while ip_queue.qsize() > 0:
        lock.acquire()
        ip = ip_queue.get()
        r = 0
        try:
            r = requests.get('http://'+str(ip),headers=headers,timeout=5)
        except requests.exceptions.ConnectionError:
            pass
        finally:
            if r != 0:
                if r.status_code == 200:
                    ip_list.append(ip)
                    #print ip
            lock.release()


def scan_host(ip_queue, ip_list, thread_num):
    threads = []
    for i in range(thread_num):
        t = threading.Thread(target=active_host_scan, args=(ip_queue, ip_list))
        #t.setDaemon(True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', dest="scanSite", help="The website to be scanned", type=str)
    parser.add_argument('-d', '--dict', dest="scanDict", help="Dictionary for scanning", type=str, default="dict/dict.txt")
    parser.add_argument('-o', '--output', dest="scanOutput", help="Results saved files", type=str, default=0)
    parser.add_argument('-t', '--thread', dest="threadNum", help="Number of threads running the program", type=int, default=60)
    parser.add_argument('-f', '--file', dest="scanInput", help="File include websites need to be scan", type=str)
    args = parser.parse_args()
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()

    # 从文件中读取目标列表
    if args.scanInput is not None:
        target_list = args.scanInput
        try:
            with open(target_list) as f:
                targets = f.readlines()
        except IOError,e:
            print "IOError: ", e
        
        for target in targets:
            try:
                scan = Dirscan(target.strip(), args.scanDict, args.scanOutput, args.threadNum)
                begin_scan(scan, args.threadNum)
            except:
                continue
    
    else:
        try:
            ips = None
            ips = IPy.IP(args.scanSite)
        except:
            pass
        # 扫描网段
        if ips is not None:
            ip_queue = Queue.Queue()
            ip_list = []
            for ip in ips:
                ip_queue.put(str(ip))
            print "begin to find active host with port 80 open..."
            scan_host(ip_queue, ip_list, args.threadNum)  # 扫描开放80端口的存活主机
            print "hosts with port 80 open are: "
            for ip in ip_list:
                print ip
            print ""           
            for ip in ip_list:
                try:
                    #print ip
                    scan = Dirscan(str(ip), args.scanDict, args.scanOutput, args.threadNum)
                    begin_scan(scan, args.threadNum)
                except:
                    continue
        # 扫描指定目标
        else:
            scan = Dirscan(args.scanSite, args.scanDict, args.scanOutput, args.threadNum)
            begin_scan(scan, args.threadNum)
            
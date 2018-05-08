#!/usr/bin/python
import urllib
import time
#import urllib2

#Needed for authentication
import hashlib
import hmac
import base64

import sys
#import requests
#requests.packages.urllib3.disable_warnings()
import json
import argparse

from params import DRYRUN, STDOUT, DOLOG, baseurl, APIKEY, SECRETKEY

class Logger():
    def __init__(self, logfile, stdout):
        self.logfile  = LOGFILE
        self.stdout = STDOUT

    def writer(self, msg):
        if LOGFILE and LOGFILE != '' and DOLOG == True:
            with codecs.open(self.logfile, 'a', encoding = 'utf-8') as f:
                try:
                  f.write(msg.strip()+'\r\n')  # \r\n for notepad
                except:
                  f.write(str(msg))
        if self.stdout == 'True' or STDOUT == True:
            try:
                print msg
            except:
                print msg.encode('ascii', 'ignore') + ' # < non-ASCII chars detected! >'

class CS():
    def getcloudstack_guestos(self):
      logger.writer('\r\n**** Cloudstack OS Types ')
      for x in range(1, 2):
        request={}
        request['command']='listOsTypes'
        request['listall']='true'
        #request['pagesize']='1'
        #request['page']='%d' % (x)
        request['apikey']=APIKEY

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])

        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())
        url=baseurl+request_str+'&signature='+sig+'&response=json'
        #url=baseurl+'&signature='+sig
        #url=baseurl
        print url+"\n"
        #print sig
        #import urllib2
        #req = urllib2.Request(url)
        #req.add_header('X-Lsw-Auth', sig)
        #resp = urllib2.urlopen(req)
        #content = resp.read()
        #print content

      content = urllib.urlopen(url).read()
      print content
      #for event,element in etree.iterparse(StringIO(xml), tag='ostype'):
        #SubnetData = {}
        #id = element.findtext('id')
        #description = element.findtext('description')

        #Add network to dictionary for adding the ip/mac to the correct subnet later on
        #CSostypeDict.update({id:description})

    def getcloudstack_networks(self):
      logger.writer('\r\n**** Cloudstack Networks ')
      for x in range(1, 2):
        request={}
        request['listall']='true'
        #request['pagesize']='1'
        #request['page']='%d' % (x)
        request['command']='listNetworks'
        request['apikey']=APIKEY

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])
        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())
        url=baseurl+request_str+'&signature='+sig
        #print url

      xml = urllib.urlopen(url).read()
      for event,element in etree.iterparse(StringIO(xml), tag='network'):
        SubnetData = {}
        id = element.findtext('id')
        name = element.findtext('name')
        gateway = element.findtext('gateway')
        netmask = element.findtext('netmask')
        cidr = element.findtext('cidr')
        zonename = element.findtext('zonename')
        domain = element.findtext('domain')

        msg = "'{0}', '{1}', '{2}','{3}','{4}','{5}','{6}'".format(id,name,gateway,netmask,cidr,zonename,domain)
        logger.writer(msg)

        SubnetData.update({'name':name})
        SubnetData.update({'network':cidr.split('/')[0]})
        SubnetData.update({'mask_bits':cidr.split('/')[1]})
        SubnetData.update({'gateway':gateway})
        SubnetData.update({'description':zonename})
        #SubnetData.update({'tags':'cloudstack'})		#Option is not available in the API (yet)
        try:
          SubnetData.update({'customer':custdict[domain]})
        except:
          msg = 'NETWORK:NOTINDICT_ERROR: %s' % domain
          logger.writer(msg)
        #print SubnetData

        #Add network to dictionary for adding the ip/mac to the correct subnet later on
        CSnetworkDict.update({id:name})

        #Post the subnet information to Device42
        rest.post_subnet(SubnetData)

    def getcloudstack_virtualmachines(self):
      logger.writer('\r\n**** Cloudstack Virtual Machines ')
      urls = []
      for x in range(1, 2):
      #for x in range(1, 2):
        request={}
        request['listall']='true'
        request['pagesize']='500'
        #request['pagesize']='5'
        request['page']='%d' % (x)
        request['command']='listVirtualMachines'
        #request['command']='listSnapshots'
        request['response']='json'
        request['apikey']=APIKEY

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])
        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())

        url=baseurl+request_str+'&signature='+sig
        #print url+'\n'
        urls.append(url)

      timestamp = int(time.time())
      hostname = 'invalid'

      raw = urllib.urlopen(url).read()
      data = json.loads(raw)

      response = data['listvirtualmachinesresponse']
      vms = response['virtualmachine']

      for vm in vms:
          id   = vm['id']
          name = vm['displayname']
          cpu  = vm['cpunumber']
          mem  = vm['memory']
          nics  = vm['nic']
          for nic in nics:
              ip   = nic['ipaddress']
          #name = i[1]
          #print name, ip, cpu, mem
          print "\nname:%s ip:%s cpucount:%s memory:%s MB id:%s" % (name,ip,cpu,mem,id)
          self.getcloudstack_list('listVolumes',id)

    def getcloudstack_list(self,type,vmid):
      #logger.writer('\r\n**** Cloudstack Volumes ')
      urls = []
      for x in range(1, 2):
      #for x in range(1, 2):
        request={}
        request['listall']='true'
        request['pagesize']='500'
        #request['pagesize']='5'
        request['page']='%d' % (x)
        #request['command']='listVirtualMachines'
        request['command']=type
        request['response']='json'
        request['apikey']=APIKEY
        if vmid and not vmid==0: request['virtualmachineid']=vmid

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])
        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())

        url=baseurl+request_str+'&signature='+sig
        #print url+'\n'
        #sys.exit()
        urls.append(url)

      raw = urllib.urlopen(url).read()
      data = json.loads(raw)

      response = data[type.lower()+'response']
      result = type.lower().replace('list','')
      result = result[:len(result)-1]
      data = response[result]

      print '  VOLUMES'
      for x in data:
          id = x['id']
          print '   ',x['name'], x['id'], x['size']/1024/1024/1024
          if 'listvolumes' in type.lower(): self.getcloudstack_listSnapshotPolicies(id)
          if 'listvolumes' in type.lower(): self.getcloudstack_snapshots(id)

    def getcloudstack_listSnapshotPolicies(self,vmid):
      #logger.writer('\r\n**** Cloudstack Volumes ')
      type = 'listSnapshotPolicies'
      urls = []
      for x in range(1, 2):
      #for x in range(1, 2):
        request={}
        request['listall']='true'
        request['pagesize']='500'
        #request['pagesize']='5'
        request['page']='%d' % (x)
        request['command']=type
        request['response']='json'
        request['apikey']=APIKEY
        if vmid and not vmid==0: request['volumeid']=vmid

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])
        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())

        url=baseurl+request_str+'&signature='+sig
        #print url+'\n'
        #sys.exit()
        urls.append(url)

      raw = urllib.urlopen(url).read()
      data = json.loads(raw)


      response = data[type.lower()+'response']
      result = type.lower().replace('list','')
      result = result.replace('icies','icy')
      #result = result[:len(result)-1]
      if len(response)>0:
          data = response[result]
          #print data

          for x in data:
              try:

                  #print id
                  #print x
                  #print '    https://cloudstack.apache.org/api/apidocs-4.7/user/createSnapshotPolicy.html'
                  print '  SNAPSHOTPOLICY'
                  #print '    snapshotpolicy: schedule(TIME), interval (hourly(0),daily(1),weekly(2),monthly(3)), maxsnaps:',x['schedule'], x['intervaltype'], x['maxsnaps']
                  #print '                    %s   %i   %i %s' % (x['schedule'], x['intervaltype'], x['maxsnaps'], x['id'])
                  #print ' schedule: time the snapshot is scheduled to be taken. Format is:* if HOURLY, MM* if DAILY, MM:HH* if WEEKLY, MM:HH:DD (1-7)* if MONTHLY, MM:HH:DD (1-28)'
                  print '              id = %s' % x['id']
                  print '        volumeid = %s' % x['volumeid']
                  print '        maxsnaps = %i' % x['maxsnaps']
                  print '    intervaltype = %i (0=hourly, 1=daily, 2=weekly, 3=monthly)' % x['intervaltype']
                  print '        schedule = %s (*, if HOURLY MM*, if DAILY MM:HH*, if WEEKLY MM:HH:DD (1-7)*, if MONTHLY MM:HH:DD (1-28))' % x['schedule']
                  print '        timezone = %s' % x['timezone']
              except:
                  print '  [!] Showing snapshots policies failed.'

    def getcloudstack_snapshots(self,volid):
      #logger.writer('\r\n**** Cloudstack Snapshots ')
      urls = []
      for x in range(1, 2):
      #for x in range(1, 2):
        request={}
        request['listall']='true'
        request['pagesize']='500'
        #request['pagesize']='5'
        request['page']='%d' % (x)
        #request['command']='listVirtualMachines'
        request['command']='listSnapshots'
        request['response']='json'
        request['apikey']=APIKEY
        if volid and not volid==0: request['volumeid']=volid

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])
        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())

        url=baseurl+request_str+'&signature='+sig
        #print url+'\n'

      raw = urllib.urlopen(url).read()
      data = json.loads(raw)

      response = data['listsnapshotsresponse']


      if int(len(data['listsnapshotsresponse'])) > 0:
          data = response['snapshot']
          print '  SNAPSHOTS'
          for x in data:
            print '   ',x['created'], x['snapshottype'], x['name'],x['state']

    def cloudstack_createSnapshot(self,volumeid):
        #https://cloudstack.apache.org/api/apidocs-4.7/user/createSnapshotPolicy.html
        #logger.writer('\r\n**** Cloudstack Volumes ')
        print volumeid

        request={}
        request['command']='createSnapshot'
        request['response']='json'
        request['apikey']=APIKEY

        request['volumeid']=volumeid

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])
        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())

        url=baseurl+request_str+'&signature='+sig
        print url+'\n'
        sys.exit()

    def cloudstack_createSnapshotPolicy(self,volumeid,intervaltype,maxsnaps,schedule,timezone):
        #https://cloudstack.apache.org/api/apidocs-4.7/user/createSnapshotPolicy.html
        #logger.writer('\r\n**** Cloudstack Volumes ')
        #print volumeid
        #print intervaltype
        #print maxsnaps
        #print schedule
        #print timezone

        request={}
        request['command']='createSnapshotPolicy'
        #request['command']='listSnapshots'
        #request['listall']='true'
        #request['pagesize']='500'
        request['response']='json'
        request['apikey']=APIKEY

        request['volumeid']=volumeid
        request['intervaltype']=intervaltype
        request['maxsnaps']=maxsnaps
        #request['schedule']='00:1:1'
        request['schedule']=schedule
        request['timezone']=timezone

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])
        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())

        url=baseurl+request_str+'&signature='+sig
        print url

        #sys.exit()
        raw = urllib.urlopen(url).read()
        #data = json.loads(raw)
        print raw


        #response = data[type.lower()+'response']
        #result = type.lower().replace('list','')
        #result = result.replace('icies','icy')
        ##result = result[:len(result)-1]
        #if len(response)>0:
        #    data = response[result]
        #
        #    for x in data:
        #        try:
        #            id = x['id']
        #            print '    snapshotpolicy: schedule(TIME), interval (hourly(0),daily(1),weekly(2),monthly(3)), maxsnaps:',x['schedule'], x['intervaltype'], x['maxsnaps']
        #            print '                    %s   %i   %i' % (x['schedule'], x['intervaltype'], x['maxsnaps'], x['id'])
        #        except:
        #            pass

    def cloudstack_deleteSnapshotPolicies(self,snapshotpolicyid):
        #https://cloudstack.apache.org/api/apidocs-4.7/user/createSnapshotPolicy.html
        #logger.writer('\r\n**** Cloudstack Volumes ')
        print snapshotpolicyid

        request={}
        request['command']='deleteSnapshotPolicies'
        #request['command']='listSnapshots'
        #request['listall']='true'
        #request['pagesize']='500'
        request['response']='json'
        request['apikey']=APIKEY

        request['id']=snapshotpolicyid

        request_str='&'.join(['='.join([k,urllib.quote_plus(request[k])]) for k in request.keys()])
        sig_str='&'.join(['='.join([k.lower(),urllib.quote_plus(request[k].lower().replace('+','%20'))])for k in sorted(request.iterkeys())])
        sig=urllib.quote_plus(base64.encodestring(hmac.new(SECRETKEY,sig_str,hashlib.sha1).digest()).strip())

        url=baseurl+request_str+'&signature='+sig

        print 'deleteSnapshotPolicies'
        raw = urllib.urlopen(url).read()
        print raw
        #sys.exit()

def main():
    usagemessage  =   'Usage: leaseweb.py -h \nMore information at: https://cloudstack.apache.org/api/apidocs-4.7/TOC_User.html'
    if len(sys.argv) < 2 :
        print usagemessage
        sys.exit()

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", help="select action: overview,listVolumes,listSnapshotPolicies,createSnapshotPolicy")
    parser.add_argument("-csv", help="createSnapShotPolicy: volumeid")
    #parser.add_argument("-csi", help="createSnapShotPolicy: intervaltype [HOURLY,DAILY,WEEKLY,MONTHLY] (default: WEEKLY)")
    #parser.add_argument("-csm", help="createSnapShotPolicy: maxsnaps (default 4)")
    parser.add_argument("-css", help="createSnapShotPolicy: schedule (default 02:00*)")
    #parser.add_argument("-cst", help="createSnapShotPolicy: timezone (default Europe/Amsterdam)")
    parser.add_argument("-snid", help="deleteSnapshotPolicies: snapshotpolicy id to remove")

    noid=0

    args = parser.parse_args()
    if args.a:
        action = args.a

    if action == 'overview':
        # Read current registrations
        cs.getcloudstack_virtualmachines()
    if 'list' in action and not 'overview' in action and not 'Snapshot' in action:
        cs.getcloudstack_list(action,noid)
    if 'listSnapshotPolicies' in action:
        cs.getcloudstack_listSnapshotPolicies('9edec2be-8197-4207-bd36-0243a52b8d1a')
    if 'createSnapshot' and not 'Polic' in action:
        if args.csv:
            csv = args.csv
            cs.cloudstack_createSnapshot(csv)
    if 'createSnapshotPolicy' in action:
        if args.csv:
            csv = args.csv
        #if args.csi:
            csi = 'weekly'
            #csi = args.csi
        #if args.csm:
            csm = '4'
            #csm = args.csm
        css = '*'
        if args.css:
            css = args.css
        #if args.cst:
            cst = 'UTC'
            #cst = args.cst
        cs.cloudstack_createSnapshotPolicy(csv,csi,csm,css,cst)
    if 'deleteSnapshotPolicies' in action:
        if args.snid:
            snid = args.snid
            cs.cloudstack_deleteSnapshotPolicies(snid)

if __name__ == '__main__':
    timestamp = int(time.time())
    LOGFILE     = str(timestamp)+'.log'
    logger = Logger(LOGFILE, STDOUT)
    cs = CS()

    main()
    print '\n[!] Done!'

    sys.exit()

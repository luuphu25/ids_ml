import urllib
import json
import pandas as pd
import numpy as np
import sys
import sklearn
import pickle
from sklearn.externals import joblib
from sklearn import preprocessing
import time
import httplib

print(pd.__version__)
print(np.__version__)
print(sys.version)
print(sklearn.__version__)
'''
def decision(result):
   if result != 0:
            arr = np.array(result)
                arr = preprocessing.scale(arr)
                predict =  clf_DoS.predict(arr)
                 l = list(predict)
            zero = l.count(0)
            one = l.count(1)
            if one != 0:
                print ">>>> Alert: DDoS ATTACK DETECTED! <<<<"
        return 0
    
    
    class staticflowpusher(object):
      
        def __init__(self, server):
            self.server = server
      
        def get(self, data):
            ret = self.rest_call({}, 'GET')
            return json.loads(ret[2])
      
        def set(self, data):
            ret = self.rest_call(data, 'POST')
            return ret[0] == 200
      
        def remove(self, objtype, data):
            ret = self.rest_call(data, 'DELETE')
            return ret[0] == 200
      
        def rest_call(self, data, action):
            path = '/wm/staticflowpusher/json'
            headers = {
                'Content-type': 'application/json',
                'Accept': 'application/json',
                }
            body = json.dumps(data)
            conn = httplib.HTTPConnection(self.server, 8080)
            conn.request(action, path, body, headers)
            response = conn.getresponse()
            ret = (response.status, response.reason, response.read())
            print ret
            conn.close()
            return ret
    def fix_ddos(ddos_flow):
        flows = ddos_flow
        flow_against_ddos = {
        'switch':"",
        "name":"",
        "cookie":"0",
        "idle_timeout":"10",
        "priority":"1",
        "in_port":"",
        "active":"true",
        
        }
        for i in xrange(0,len(ddos_flow)):
    	flow_against_ddos['switch'] = flows[i][0]
    	flow_against_ddos['name'] = 'flow'+ str(i)
    	flow_against_ddos['cookie'] = str(10000 + i)
    	flow_against_ddos['in_port'] = flows[i][3]
    	pusher = staticflowpusher('192.168.2.129')
    	pusher.set(flow_against_ddos)
    	print "Set flow: " 
    	print flow_against_ddos
    '''
def pharse_flows(flows, IDS):
    ddos_flow = []
    phars_data = []
    backup_flow = []
    if not (flows[1].has_key('flows')):
        return 0, ddos_flow
    n_flows = len(flows[1]['flows'])
    if n_flows > 0:
        print "Flows detected:" + str(n_flows)
    if n_flows == 0:
	return 0, ddos_flow
    count_connection = {}
    n_count = -1
    ddos = 0
    i = 0
    while i < n_flows :
        entry_flows = flows[1]['flows'][i]
        switch = flows[0]
        if entry_flows['cookie'] == '0':
            continue
        duration = entry_flows['duration_sec']
        src_bytes = entry_flows['byte_count']
        dst_bytes = '0'
        protocol_type = 'icmp' #mac dinh
        eth_src = entry_flows['match']['eth_src']
        eth_dst = entry_flows['match']['eth_dst']
        in_port = entry_flows['match']['in_port']
        if eth_src + eth_dst not in count_connection:
            count_connection[eth_src + eth_dst + in_port] = 1
        else:
            count_connection[eth_src + eth_dst + in_port] += 1
            continue

        if entry_flows['match'].has_key('ipv4_dst'):
            ip_dst = entry_flows['match']['ipv4_dst']
            # tim kiem luong reply
            #for j in xrange(0, n_flows):
            if i  < n_flows -1:
                search_flows = flows[1]['flows'][i+1]
                if search_flows['match'].has_key('ipv4_dst') :
                        if (search_flows['match']['ipv4_src'] == ip_dst) and (eth_dst == search_flows['match']['eth_src']):
                                dst_bytes = search_flows['byte_count']
                                i = i + 1
                                
#            if i > 0:
#                search_flows = flows[1]['flows'][i-1]
#                if search_flows['match'].has_key('ipv4_dst') :
#                        if (search_flows['match']['ipv4_src'] == ip_dst) and (eth_dst == search_flows['match']['eth_src']):
#                                dst_bytes = search_flows['byte_count']
        if entry_flows['match'].has_key('ip_proto'):
            if entry_flows['match']['ip_proto'] == '0x6':
                protocol_type = 'tcp'
            elif entry_flows['match']['ip_proto'] == '0x11':
                protocol_type = 'udp'
            else:
                protocol_type = 'icmp'


        phars_arr = []
        b_arr = []

        phars_arr.append(duration)
        phars_arr.append(src_bytes)
        phars_arr.append(dst_bytes)
        phars_arr.append(n_count)
        phars_arr.append(n_count)
        
        if protocol_type == 'tcp':
            phars_arr.append('0.0')
            phars_arr.append('1.0')
            phars_arr.append('0.0')
        elif protocol_type == 'icmp':
            phars_arr.append('1.0')
            phars_arr.append('0.0')
            phars_arr.append('0.0')
        else:
            phars_arr.append('0.0')
            phars_arr.append('0.0')
            phars_arr.append('1.0')
        phars_arr.append(eth_src)
        phars_arr.append(eth_dst)
        phars_arr.append(in_port)
        b_arr.append(switch)
        b_arr.append(eth_src)
        b_arr.append(eth_dst)
        b_arr.append(in_port)
        b_arr.append(n_flows)
        phars_data.append(phars_arr)
        backup_flow.append(b_arr)
        i = i + 1
    for i in xrange(len(phars_data)):
        n_count =  count_connection[phars_data[i][8] + phars_data[i][9]+ phars_data[i][10]]
        phars_data[i][3] = n_count
        phars_data[i][4] = n_count
        phars_data[i] = phars_data[i][:8]
        result = np.array(phars_data[i])
        #print result
        result = np.array(result)
        result = preprocessing.scale(result)
        predict =  IDS.predict([result])
    
        if np.array_equal(predict,[1]):
            ddos_flow.append(backup_flow[i])
          #ddos += 1
          #if ddos > (n_flows * 0.75):
            return 2, ddos_flow

    return 0,ddos_flow


clf_DoS = joblib.load('IDS_ML.pkl')
print "Loading IDS machine learning successful !"

ddos = 0

url = "http://192.168.6.129:8080/wm/core/switch/all/flow/json"

while True:
    ddos = 0
    ddos_flow = []
    temp_flow = []
    print "Monitoring data flows...."
    response = urllib.urlopen(url)
    data = json.loads(response.read())
    #print data
    flag = -1
    s1 = data.items()[0]
    s2 = data.items()[1]
    s3 = data.items()[2]

    flag, temp_flow = pharse_flows(s1, clf_DoS)
    ddos_flow += temp_flow
    if flag == 2:
            #print s1	
            ddos += 1
    flag,temp_flow = pharse_flows(s2, clf_DoS)
    ddos_flow += temp_flow
    if flag == 2:
        #print s2
        ddos += 1
    flag, temp_flow = pharse_flows(s3, clf_DoS)
    ddos_flow += temp_flow
    if flag == 2:
        #print s3
        ddos += 1

    if ddos > 1:        
        print ">>>> Alert: DDoS ATTACK DETECTED! <<<<"
        print len(ddos_flow)
    time.sleep(4)


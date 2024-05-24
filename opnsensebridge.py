#!/usr/bin/env python3
import requests
import json
import ipaddress
import sys
import os
import urllib

def getservers(opnsenseURL, APIkey, APIsecret):
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/searchServer/',
                    auth=(APIkey, APIsecret), verify=True)
    if r.status_code != 200:
        print(r.text)
        sys.exit()

    list=[{'uuid':item['uuid'],'interface':item['interface'],'name':item['name']} for item in r.json()['rows']]
    print('{"arr":'+json.dumps(list)+'}')

def getclients(opnsenseURL, APIkey, APIsecret):
    r = requests.get(f'{opnsenseURL}/api/wireguard/client/searchClient/',
                    auth=(APIkey, APIsecret), verify=True)
    if r.status_code != 200:
        print(r.text)
        sys.exit()
    return r.json()['rows']

def getoverlappingnetworks(Realms, Realm):
    overlapping = [ipaddress.ip_network(entry) for entry in sum([item.split(",") for item in Realms], []) if ipaddress.ip_network(entry).overlaps(Realm)]
    return overlapping

def getip(opnsenseURL, APIkey, APIsecret, tunnelRealm):

    try:
        tunnelNetwork = ipaddress.ip_network(tunnelRealm)
    except:
        print('Tunnel Address "' + tunnelRealm + '" is not valid.')
        sys.exit()
    if not tunnelNetwork.num_addresses > 1:
        print('Only 1 network address given as Tunnel Realm.')
        sys.exit()

    occupiedNetworks = getoverlappingnetworks([client['tunneladdress'] for client in getclients(opnsenseURL, APIkey, APIsecret)],tunnelNetwork)

    occupiedHosts = []
    for occupiedNetwork in occupiedNetworks:
            occupiedHosts += set(occupiedNetwork.hosts())
    usableHosts = sorted(set(tunnelNetwork.hosts()) -
                    set(occupiedHosts))
    usableHost = next(item for item in usableHosts if item > list(tunnelNetwork.hosts())[0]+9)

    print('{"ip":"'+usableHost.exploded+'/32"}')

def createclient(opnsenseURL, APIkey, APIsecret, PeerName, pubkey, pskey, tunnelAddress):
    wireguardsClients = getclients(opnsenseURL, APIkey, APIsecret)

    if PeerName in [item["name"] for item in wireguardsClients]:
        print('Client name exists. This is OPNsense-wise valid, but not recommended. Make manual configuration in WebGUI if wanted.')
        sys.exit()

    try:
        tunnelNetwork=ipaddress.ip_network(tunnelAddress)
    except:
        print('Tunnel Address "' + tunnelAddress + '" is not valid.')
        sys.exit()

    overlapping = getoverlappingnetworks([client['tunneladdress'] for client in wireguardsClients],tunnelNetwork)

    if overlapping:
        print('Client Adress overlaps with existing tunnels. This is OPNsense-wise valid, but not recommended. Make manual configuration in WebGUI if wanted.')
        sys.exit()

    createObject = {
        "client": {
            "enabled": '1',
            "name": PeerName,
            "pubkey": pubkey,
            "psk": pskey,
            "tunneladdress": tunnelAddress,
            "keepalive ": '25'
        }
    }

    r = requests.post(f'{opnsenseURL}/api/wireguard/client/addClient/', data=json.dumps(createObject),
                    headers={'content-type': 'application/json'}, auth=(APIkey, APIsecret), verify=True)
    if r.status_code != 200:
        print(r.text)
        sys.exit()

    if r.json()["uuid"]:
        print('{"uuid":"'+r.json()["uuid"]+'"}')
    else:
        print(r.text)
        sys.exit()

def enableclient(opnsenseURL, APIkey, APIsecret, ServerUUID, PeerUUID):

    # get currently selected peers from server
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/getServer/{ServerUUID}',
                    auth=(APIkey, APIsecret), verify=True)
    if r.status_code != 200:
        print(r.text)
        sys.exit()

    ServerPeers = r.json()['server']['peers']
    selectedPeers = [peer for peer in ServerPeers if ServerPeers[peer]['selected']]

    peersToSelect = ','.join(selectedPeers + [PeerUUID])

    wireguardInstanceInfo = {'server': {'peers': peersToSelect}}
    r = requests.post(f'{opnsenseURL}/api/wireguard/server/setServer/{ServerUUID}', data=json.dumps(
        wireguardInstanceInfo), headers={'content-type': 'application/json'}, auth=(APIkey, APIsecret), verify=True)
    print(r.text)

def reconfigure(opnsenseURL, APIkey, APIsecret):
    r = requests.post(f'{opnsenseURL}/api/wireguard/service/reconfigure', data='{}',
                    headers={'content-type': 'application/json'}, auth=(APIkey, APIsecret), verify=True)
    print(r.text)


print("Content-type: text/html\n\n")

form=urllib.parse.parse_qs(os.environ['QUERY_STRING'])
match form['task'][0]:
    case "getservers":
        getservers(form['opnsenseURL'][0],form['key'][0],form['secret'][0])
    case "getip":
        getip(form['opnsenseURL'][0],form['key'][0],form['secret'][0],form['tunnelRealm'][0])
    case "createclient":
        uuid = createclient(form['opnsenseURL'][0],form['key'][0],form['secret'][0],form['PeerName'][0],form['pubkey'][0],form['pskey'][0],form['tunnelAddress'][0])
    case "enableclient":
        enableclient(form['opnsenseURL'][0],form['key'][0],form['secret'][0],form['ServerUUID'][0],form['PeerUUID'][0])
    case "reconfigure":
        reconfigure(form['opnsenseURL'][0],form['key'][0],form['secret'][0])


#!/usr/bin/env python
from __future__ import print_function

import argparse
from functools import partial
import requests

import phue
from scapy.all import *

MAX_PHONE_INTERVAL = 1200 # assume phone has left the house if not active after this many seconds

def switch_lights(state, switch_on):
  if not switch_on:
    state['lights_to_turn_on'] = [light.light_id for light in state['all_lights_group'].lights if light.on]
  print('Switching %s %d lights' % ('on' if switch_on else 'off', len(state['lights_to_turn_on'])))
  hue.set_light(state['lights_to_turn_on'], 'on', switch_on)
  if switch_on:
    state['lights_to_turn_on'] = []


def lookup_mac_address(mac_address):
  try:
    rec = requests.get('http://macvendors.co/api/' + mac_address).json()
  except requests.RequestException:
    return ''
  if rec.get('result'):
    return rec['result'].get('company', '')
  return ''


def arp_display(state, pkt):
  if pkt.haslayer(ARP): # and pkt[ARP].op == 1:
    mac_address = pkt[ARP].hwsrc
    if time.time() - state['last_press'] > 5 and mac_address == state['dash_mac']:
      # button press
      if state['lights_to_turn_on']:
        switch_lights(state, True)
      else:
        switch_lights(state, False)
      state['last_press'] = time.time()

    if not mac_address in state['seen']:
      print('new mac address:', mac_address, lookup_mac_address(mac_address))
      state['seen'].add(mac_address)

    if state['phone_macs']:
      if mac_address in state['phone_macs']:
        state['last_phone_seen'] = time.time()

      phone_interval = time.time() - state['last_phone_seen']
      if state['anybody_home'] and phone_interval > MAX_PHONE_INTERVAL:
        print('Nobody home any more')
        state['anybody_home'] = False
        if not state['lights_to_turn_on']:
          switch_lights(state, False)
      elif not state['anybody_home'] and phone_interval < MAX_PHONE_INTERVAL:
        print('Somebody came home')
        state['anybody_home'] = True
        if state['lights_to_turn_on']:
          switch_lights(state, True)



if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Auto lights')
  parser.add_argument('--hue_bridge', type=str, default='')
  parser.add_argument('--phone_macs', nargs='*')
  parser.add_argument('--dash_mac', type=str)
  args = parser.parse_args()

  hue = phue.Bridge(args.hue_bridge)
  phone_macs = args.phone_macs or []
  state = {'all_lights_group': phue.AllLights(hue),
           'dash_mac': args.dash_mac,
           'anybody_home': True,
           'last_phone_seen': time.time(),
           'phone_macs': set(phone_macs),
           'seen': {m for m in phone_macs + [args.dash_mac]},
           'last_press': time.time(),
           'lights_to_turn_on': []}
  print('hue initialized %d lights' % (len(state['all_lights_group'].lights)))

  sniff(prn=partial(arp_display, state), filter="arp", store=0, count=0)
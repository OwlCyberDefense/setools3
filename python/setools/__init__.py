#!/usr/bin/env python

# Author: Thomas Liu <tliu@redhat.com>

import _sesearch
import _seinfo
import types

TYPE = _seinfo.TYPE
ROLE = _seinfo.ROLE
ATTRIBUTE = _seinfo.ATTRIBUTE
PORT = _seinfo.PORT
USER = _seinfo.USER

ALLOW = 'allow'
AUDITALLOW = 'auditallow'
NEVERALLOW = 'neverallow'
DONTAUDIT = 'dontaudit'
SCONTEXT = 'scontext'
TCONTEXT = 'tcontext'
PERMS = 'permlist'
CLASS = 'class'

def sesearch(types, info):
    valid_types = [ALLOW, AUDITALLOW, NEVERALLOW, DONTAUDIT]
    for type in types:
        if type not in valid_types:
            raise ValueError("Type has to be in %s" % valid_types)
        info[type] = True

    perms = []
    if PERMS in info:
        perms = info[PERMS]
        info[PERMS] = ",".join(info[PERMS])
     
    
    dict_list = _sesearch.sesearch(info)
    if dict_list and len(perms) != 0:
        dict_list = filter(lambda x: dict_has_perms(x, perms), dict_list)
    return dict_list

def dict_has_perms(dict, perms):
    for perm in perms:
        if perm not in dict[PERMS]:
            return False
    return True

def seinfo(setype, name=None):
    dict_list = _seinfo.seinfo(setype, name)
    return dict_list

#!/usr/bin/env python
#
# sync ad groups to ldap - crpeck 20130628


import argparse
import sys
import string
import ldap
import ldap.modlist as modlist
from ConfigParser import SafeConfigParser

__author__ = 'crpeck@wm.edu'
searchscope = ldap.SCOPE_SUBTREE

parser = argparse.ArgumentParser(description='Sync Groups from Active Directory to LDAP')
parser.add_argument('-c','--configfile', help='Configuration File Name',default='syncgroups-ad2ldap.ini')
parser.add_argument('-s','--searchfilter', help='LDAP Search Filter',default='cn=*')
args = parser.parse_args()
configfile = args.configfile
searchfilter = args.searchfilter

parser = SafeConfigParser()
parser.read(configfile)

print configfile,searchfilter

# read in AD configs
adserver = parser.get('ad', 'adserver')
adbasedn = parser.get('ad', 'adbasedn')
adbinduser = parser.get('ad', 'adbinduser')
adbindpass = parser.get('ad', 'adbindpass')

# read in ldap configs
ldapserver = parser.get('ldap', 'ldapserver')
ldapbasedn = parser.get('ldap', 'ldapbasedn')
ldapbinduser = parser.get('ldap', 'ldapbinduser')
ldapbindpass = parser.get('ldap', 'ldapbindpass')

#Active Directory Server Connection
try:
    ad=ldap.initialize(adserver)
except:
    print "cannot initialize:",adserver
    exit(1)
try:
    ad.simple_bind_s(adbinduser,adbindpass)
except ldap.LDAPError, e:
    print "cannot bind to:",adserver,"as ",adbinduser
    exit(1)

#ldap Server Connection
try:
    ld=ldap.initialize(ldapserver)
except ldap.LDAPError, e:
    print "cannot initialize:",ldapserver
    exit(1)
try:
    ld.simple_bind_s(ldapbinduser,ldapbindpass)
except:
    print "cannot bind to:",ldapserver,"as ",ldapbinduser
    exit(1)

adgroups = ad.search_s(adbasedn, searchscope, searchfilter)
adnumgroups = len(adgroups)

ldapgroups = ld.search_s(ldapbasedn, searchscope, searchfilter)
ldapnumgroups = len(ldapgroups)

numgroupsadded = 0

if adnumgroups == 0:
    print "AD Group search returned %d AD Groups" % adnumgroups
    print "Exiting"
    exit(1)

# build a list of groupnames already in ldap
ldapgroupnames = [ ]
try:
    for (dn,group) in ldapgroups:
        try:
            ldapgroupnames.append(''.join(group['cn']))
        except:
            pass
except:
        print "Note - no groups in ",ldapbasedn

# get AD groups, add the group as needed

try:
    for (dn,group) in adgroups:
        try:
            groupname = ''.join(group['sAMAccountName'])
        except:
            print 'No groupname for',dn
        try:
            gid = ''.join(group['gidNumber'])
        except:
            print 'no gidnumber for',dn

        ldapcn = "cn=%s," % groupname
        ldapdn = ldapcn+ldapbasedn

        # if group is NOT already in LDAP then create it
        if groupname not in ldapgroupnames:
            attrs = {}
            attrs['objectclass'] = ['top','posixGroup']
            attrs['cn'] = groupname
            attrs['gidNumber'] = gid
            print "adding group",ldapdn,attrs
            try:
                ldif = modlist.addModlist(attrs)
                ld.add_s(ldapdn,ldif)
                numgroupsadded += 1
            except ldap.ldapError, error_message:
                ldapadDERROR=1
                print 'error adding group', error_message

        # update members in group in LDAP
        try:
            members = group['member']
            newmembers = []
            for member in members:
                try:
                    memberuid = member[member.find("CN=")+3:member.find(",OU")]
                except:
                    print 'no memberuid for',member[member.find("CN=")+3:member.find(",OU")]
                try:
                    newmembers.append(memberuid)
                except:
                    print "cannot append to newmembers"
    
            mod_members = [(ldap.MOD_REPLACE, 'memberUID', newmembers)]
            ld.modify_s(ldapdn, mod_members)
        except:
            print "No members in:", ldapdn, member

except:
    pass


ad.unbind_s()
ld.unbind_s()

print "\nCurrent Count of Groups"
print "Number of AD Groups:    ",adnumgroups
print "Number of LDAP Groups:  ",ldapnumgroups
print
print "Number of Groups Added: ",numgroupsadded

exit(0)

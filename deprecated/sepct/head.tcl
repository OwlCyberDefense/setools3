#!/bin/sh
# the next line restarts using wish \
exec wish "$0" "$@"
              
##############################################################
# top.tcl (top level name space)
#
# SePCuT: SE Linux Security Policy Customization Tool
#
# Copyright (C) 2002-2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 
#
# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets
# Author(s): <don.patterson@tresys.com, mayerf@tresys.com>
# Question/comments to: selinux@tresys.com
#
# This tool is designed as a basic customization and editing
# tool for selinux security policy source directory files.
# This tool will allow you to include/exclude/add/delete policy
# program modules, and browse and edit all policy source
# files.  In addition, it will allow you to test, debug,
# load, and install the policy.  

# See the assoicated help file for more information.
#
##############################################################

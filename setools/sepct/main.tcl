#! /usr/bin/wish


##############################################################
#
# SePCuT: SE Linux Security Policy Customization Tool
#
# Copyright (C) 2002-2003 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 
#
# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets
#
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

##############################################################
#
# This name space contains global, tool-wide setting you can 
# configure by editing the values of the assoicated variable.
# Since the tool doesn't current support a ~/.sepcut file, 
# this is the best you can do for now for customizing the tool
#
##############################################################

namespace eval Sepct_Main {
	# This var determine whether the tool starts in edit or read-only mode
	# 	(0 read only, 1 edit mode
	variable initial_edit_mode	1
	
	# This var, if defined with something other than "", determines
	# what policy directory will open (load) by default.
	#variable inital_policy_dir	"/etc/security/selinux/src/policy/"
	variable inital_policy_dir	""
	
	# This var determines whether modules are listed using descriptive
	# name (0) or file name (1), by default, in the customize tab
	variable show_customize_file_names	0
}

# If a policy dir is given at the command line, ignore the default initial policy dir from above .
set argv1 [lindex $argv 0]
if { $argv1 != "" } {
	set Sepct_Main::inital_policy_dir $argv1
}

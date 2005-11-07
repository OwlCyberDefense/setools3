#############################################################
#  foo_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003-2005 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com, mayerf@tresys.com>
# -----------------------------------------------------------
#
##
## This module is not a real analysis, but a simple same that also 
## serves as a guide to what one must do when creating a module via
## embedded comments.  This file also serves as a template for when
## new analysis modules are created.  To include this module in apol,
## add the file name to the ANALYSIS-MODULES variable in the 
## Makefile.
#
# All this module does is display an entry box and echo the contents
# of that box.

##############################################################
# ::Apol_Analysis_foo module namespace
##############################################################

## The name space should following the convention of Apol_Analysis_XXX, where
## XXX is a 3-4 letter name for the analysis.
namespace eval Apol_Analysis_foo {
	# Display variables
    	variable entry_string_display	""
    	# State variables
    	variable entry_string_state	""
    	
    	# Global widgets
    	variable sEntry	""
    	variable descriptive_text "This is an analysis template dialog that simply displays the content of the \
		entry box.  The purpose of this analysis is to provide a template for new analyses."
    	
## Within the namespace command for the module, you must call Apol_Analysis::register_analysis_modules,
## the first argument is the namespace name of the module, and the second is the
## descriptive display name you want to be displayed in the GUI selection box.
    	Apol_Analysis::register_analysis_modules "Apol_Analysis_foo" "Analysis template example (foo)"
}

## Apol_Analysis_XXX::initialize is called when the tool first starts up.  The
## analysis has the oppertunity to do any additional initialization it must  do
## that wasn't done in the initial namespace eval command.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::initialize
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::initialize { } {    
     	
     	return 0
}

## Command Apol_Analysis_XXX::do_analysis is the principal interface command.
## The GUI will call this when the module is to perform it's analysis.  The
## module should know how to get its own option information (the options
## are displayed via ::display_mod_options
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::do_analysis { results_frame } {  
	variable entry_string_display	
	if {$entry_string_display == "" } {
		return -code error "You must enter text in the entry box."
	}
     	set results_box [text $results_frame.results_box -bg white -wrap none -font {$ApolTop::text_font }]
     	pack $results_box -expand yes -fill both
     	$results_box insert 0.0 $entry_string_display
     	return 0
} 

## Apol_Analysis_XXX::close must exist; it is called when a policy is closed.
## Typically you should reset any context or option variables you have.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::close
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::close { } {   
	Apol_Analysis_foo::clear_results
     	return 0
} 

## Apol_Analysis_XXX::open must exist; it is called when a policy is opened.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::open
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::open { } {   	
     	return 0
} 

## Apol_Analysis_XXX::clear_results is called ????????
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::clear_results
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::clear_results { } {   
	Apol_Analysis_foo::reset_variables  	
     	return 0
} 

## Apol_Analysis_XXX::display_mod_options is called by the GUI to display the
## analysis options interface the analysis needs.  Each module must know how
## to display their own options, as well bind appropriate commands and variables
## with the options GUI.  opts_frame is the name of a frame in which the options
## GUI interface is to be packed.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::display_mod_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::display_mod_options { opts_frame } {    
	Apol_Analysis_foo::reset_variables 	
     	Apol_Analysis_foo::create_options $opts_frame
     	return 0
} 

## Apol_Analysis_XXX::get_analysis_info is called by the GUI to retrieve
# descriptive text, which provides it's analysis information. Each module must
# return descriptive text.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::get_analysis_info
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::get_analysis_info {} {
     	return $Apol_Analysis_foo::descriptive_text
} 

## Apol_Analysis_XXX::load_query_options is called by the GUI to 
## set the query options in the GUI with the given query options. 
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::load_query_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::load_query_options { file_channel parentDlg } {   
	variable entry_string_state
     	
     	set query_options ""
        while {[eof $file_channel] != 1} {
		gets $file_channel line
		set tline [string trim $line]
		# Skip empty lines and comments
		if {$tline == "" || [string compare -length 1 $tline "#"] == 0} {
			continue
		}
		set query_options [lappend query_options $tline]
	}
	if {$query_options == ""} {
		return -code error "No query parameters were found."
	}
	# Re-format the query options list into a string where all elements are seperated
	# by a single space. Then split this string into a list using the space as the delimeter.	
	set query_options [split [join $query_options " "]]
	
     	if {[lindex $query_options 0] != "\{\}"} {
     		set entry_string_state [lindex $query_options 0]
     	}
     	Apol_Analysis_foo::update_display_variables
     	# After updating any display variables, must configure widgets accordingly
	return 0
} 

## Apol_Analysis_XXX::save_query_options is called by the GUI to save
## the analysis's current result query parameters to a file on disk. 
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::save_query_options
#	- module_name - name of the analysis module
#	- file_channel - file channel identifier of the query file to write to.
#	- file_name - name of the query file
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::save_query_options {module_name file_channel file_name} {  
	variable entry_string_display 
	   	
     	set options [list $entry_string_display]
     
     	puts $file_channel "$module_name"
	puts $file_channel "$options"
     	return 0
} 

## Apol_Analysis_XXX::get_current_results_state is called by the GUI to get
## the analysis's current result query parameters. The GUI calls this when it plans to
## switch views and wants to restore the current query options displayed.
## This proc should return a list containing whatever context the analysis
## wants to store so that it can restore the options when asked to.  The
## GUI will treat the returned list as opaque and will not attempt to 
## interpret the list.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::get_current_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::get_current_results_state { } {  
	variable entry_string_display 
	variable sEntry    	
     	return [list $sEntry $entry_string_display]
} 

## Apol_Analysis_XXX::set_display_to_results_state is called to reset the options
## or any other context that analysis needs when the GUI switches back to an
## existing analysis.  options is a list that we created in a previous 
## get_current_results_state() call.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::set_display_to_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::set_display_to_results_state { query_options } {     	
     	variable entry_string_state
     	variable sEntry 
     	
     	# results tab widget variables
     	set sEntry [lindex $query_options 0]
     	# query options variables
     	set entry_string_state [lindex $query_options 1]
     	Apol_Analysis_foo::update_display_variables
     	# After updating any display variables, must configure widgets accordingly
     	return 0
} 

## Apol_Analysis_foo::free_results_data is called to destroy subwidgets 
#  under a results frame as well as free any data associated with them.
#  query_options is a list that we created in a previous get_current_results_state() call,
#  from which we extract the subwidget pathnames for the results frame.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::free_results_data
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::free_results_data {query_options} {  
	set sEntry [lindex $query_options 1]
	
	if {[winfo exists $sEntry]} {
		set Apol_Analysis_foo::entry_string_display ""
		destroy $sEntry
	}
	return 0
}

#################################################################################
#################################################################################
##
## The rest of these procs are not interface procedures, but rather internal
## functions to this analysis.
##
#################################################################################
#################################################################################

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::reset_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::reset_variables { } {   
	set Apol_Analysis_foo::entry_string_display	"" 
	set Apol_Analysis_foo::entry_string_state	""
	set sEntry ""
     	return 0
} 
 
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::update_display_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::update_display_variables {  } {
	variable entry_string_display
	set entry_string_display $Apol_Analysis_foo::entry_string_state
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_foo::create_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_foo::create_options { options_frame } {
	variable sEntry
	
	set entry_frame [frame $options_frame.entry_frame]
	set sLabel [Label $entry_frame.sLabel -text "Enter Text:"]
    	set sEntry [Entry $entry_frame.sEntry -textvariable Apol_Analysis_foo::entry_string_display -width 25 -background white]
        	
	pack $entry_frame -side left -fill y -padx 10
	pack $sLabel $sEntry -side top -anchor nw
	return 0	
}

proc Apol_Analysis_foo::get_short_name {} {
    return "Foo"
}

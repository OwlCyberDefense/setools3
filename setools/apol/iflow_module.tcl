#############################################################
#  iflow_module.tcl  
# -----------------------------------------------------------
#  Copyright (C) 2003 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information 
#
#  Requires tcl and tk 8.3+, with BWidgets
#  Author: <don.patterson@tresys.com, mayerf@tresys.com, kcarr@tresys>
# -----------------------------------------------------------
#
# This is the implementation of the interface for Information
# Flow analysis.

##############################################################
# ::Apol_Analysis_iflow module namespace
##############################################################

namespace eval Apol_Analysis_iflow {
        variable sEntry ""
     	variable combo_attribute
	variable display_attrib_sel
        variable display_type
        variable list_objs
        variable objects_sel
	# Display variables
        variable start_type ""
        variable entry_end
        variable endtype_sel
        variable end_type
    	# State variables
    	variable start_state	""
        variable end_state       ""
    	
    	# Global widgets
    	variable descriptive_text "This analysis option allows you to make queries on information flow \
		capabilities between object types in the current policy."
    	
## Within the namespace command for the module, you must call Apol_Analysis::register_analysis_modules,
## the first argument is the namespace name of the module, and the second is the
## descriptive display name you want to be displayed in the GUI selection box.
    	Apol_Analysis::register_analysis_modules "Apol_Analysis_iflow" "Information Flow Analysis"
}

## Apol_Analysis_iflow::initialize is called when the tool first starts up.  The
## analysis has the opportunity to do any additional initialization it must  do
## that wasn't done in the initial namespace eval command.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::initialize
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::initialize { } {    
     	
     	return 0
}

## Command Apol_Analysis_iflow::do_analysis is the principal interface command.
## The GUI will call this when the module is to perform it's analysis.  The
## module should know how to get its own option information (the options
## are displayed via ::display_mod_options
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::do_analysis { results_frame } {  
	variable start_type
        variable end_type
        variable sEntry

	if {$start_type == "" } {
		return -code error "You must enter text in the 'Starting Type' box."
	}
     	set results_box [text $results_frame.results_box -bg white -wrap none -font {$ApolTop::text_font }]
     	pack $results_box -expand yes -fill both
     	$results_box insert 0.0 $start_type
     	return 0
} 

## Apol_Analysis_iflow::close must exist; it is called when a policy is closed.
## Typically you should reset any context or option variables you have.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::close
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::close { } {   
puts "close function"
	Apol_Analysis_iflow::clear_results
     	return 0
} 

## Apol_Analysis_iflow::open must exist; it is called when a policy is opened.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::open
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::open { } {   	
     	return 0
} 

## Apol_Analysis_iflow::clear_results is called ????????
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::clear_results
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::clear_results { } {   
	Apol_Analysis_iflow::reset_variables  	
     	return 0
} 

## Apol_Analysis_iflow::set_display_to_results_state is called to reset the options
## or any other context that analysis needs when the GUI switches back to an
## existing analysis.  options is a list that we created in a previous 
## get_current_results_state() call.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::set_display_to_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::set_display_to_results_state { options } {     	
     	variable start_state
     	variable sList 
     	
     	set start_state [lindex $options 0]
     	set sList [lindex $options 1]
     	Apol_Analysis_iflow::update_display_variables
     	# After updating any display variables, must configure widgets accordingly
     	return 
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
#  Command Apol_Analysis_iflow::reset_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::reset_variables { } {   
	set Apol_Analysis_iflow::start_type     	"" 
	set Apol_Analysis_iflow::start_state	        ""
        set Apol_Analysis_iflow::end_type               ""
        set Apol_Analysis_iflow::end_state              ""
        set Apol_Analysis_iflow::sEntry                 ""
     	return 0
} 
 
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::update_display_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::update_display_variables {  } {
	variable start_type
	set start_type $Apol_Analysis_iflow::start_type
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::config_attrib_comboBox_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::config_attrib_comboBox_state { } {    
     	variable combo_attribute
	variable display_attrib_sel 	
	
	if { $display_attrib_sel } {
		$combo_attribute configure -state normal -entrybg white
	} else {
		$combo_attribute configure -state disabled -entrybg  $ApolTop::default_bg_color
	}
	
     	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::config_endtype_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::config_endtype_state { } {
        variable entry_end
        variable endtype_sel

        if { $endtype_sel } {
	        $entry_end configure -state normal -background white
	} else {
	        $entry_end configure -state disabled -background $ApolTop::default_bg_color
	}
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::config_objects_list_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::config_objects_list_state { } {
        variable list_objs
        variable objects_sel

        if { $objects_sel } {
	        $list_objs configure -background white
	} else {
	        $list_objs configure -background $ApolTop::default_bg_color
	}
        return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_dta::change_types_list
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::change_types_list { } { 

        return 0
}


## Apol_Analysis_iflow::initialize is called when the tool first starts up.  The
## analysis has the opportunity to do any additional initialization it must  do
## that wasn't done in the initial namespace eval command.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::initialize
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::initialize { } {    
     	
     	return 0
}

## Command Apol_Analysis_iflow::do_analysis is the principal interface command.
## The GUI will call this when the module is to perform it's analysis.  The
## module should know how to get its own option information (the options
## are displayed via ::display_mod_options
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::do_analysis
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::do_analysis { results_frame } {  
	variable start_type
        variable end_type
        variable sEntry

	if {$start_type == "" } {
		return -code error "You must enter text in the 'Starting Type' box."
	}
     	set results_box [text $results_frame.results_box -bg white -wrap none -font {$ApolTop::text_font }]
     	pack $results_box -expand yes -fill both
     	$results_box insert 0.0 $start_type
     	return 0
} 

## Apol_Analysis_iflow::close must exist; it is called when a policy is closed.
## Typically you should reset any context or option variables you have.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::close
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::close { } {
	Apol_Analysis_iflow::clear_results
     	return 0
} 

## Apol_Analysis_iflow::open must exist; it is called when a policy is opened.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::open
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::open { } {   	
     	return 0
} 

## Apol_Analysis_iflow::clear_results is called ????????
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::clear_results
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::clear_results { } {   
	Apol_Analysis_iflow::reset_variables  	
     	return 0
} 

## Apol_Analysis_iflow::set_display_to_results_state is called to reset the options
## or any other context that analysis needs when the GUI switches back to an
## existing analysis.  options is a list that we created in a previous 
## get_current_results_state() call.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::set_display_to_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::set_display_to_results_state { options } {     	
     	variable start_state
     	variable sList 
     	
     	set start_state [lindex $options 0]
     	set sList [lindex $options 1]
     	Apol_Analysis_iflow::update_display_variables
     	# After updating any display variables, must configure widgets accordingly
     	return 
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
#  Command Apol_Analysis_iflow::reset_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::reset_variables { } {   
	set Apol_Analysis_iflow::start_type     	"" 
	set Apol_Analysis_iflow::start_state	""
        set Apol_Analysis_iflow::end_type               ""
        set Apol_Analysis_iflow::end_state         ""
        set Apol_Analysis_iflow::sEntry                 ""
     	return 0
} 
 
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::update_display_variables
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::update_display_variables {  } {
	variable start_type
	set start_type $Apol_Analysis_iflow::start_type
	return 0
}

## Apol_Analysis_iflow::display_mod_options is called by the GUI to display the
## analysis options interface the analysis needs.  Each module must know how
## to display their own options, as well bind appropriate commands and variables
## with the options GUI.  opts_frame is the name of a frame in which the options
## GUI interface is to be packed.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::display_mod_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::display_mod_options { opts_frame } {    
	Apol_Analysis_iflow::reset_variables 	
     	Apol_Analysis_iflow::create_options $opts_frame
     	return 0
} 

## Apol_Analysis_iflow::get_current_results_state is called by the GUI to get
## the analysis's current result options.  The GUI calls this when it plans to
## switch views and wants to store the current options so it can be restored.
## This proc should return a list containing whatever context the analysis
## wants to store so that it can restore the options when asked to.  The
## GUI will treat the returned list as opaque and will not attempt to 
## interpret the list.
# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::get_current_results_state
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::get_current_results_state { } {  
	variable start_type
     	variable sList   	     	
        variable sEntry

     	return [list $start_type $sEntry]
} 

# ------------------------------------------------------------------------------
#  Command Apol_Analysis_iflow::create_options
# ------------------------------------------------------------------------------
proc Apol_Analysis_iflow::create_options { options_frame } {
     	variable combo_attribute
	variable display_attrib_sel 
        variable display_attribute
        variable descriptive_text
        variable start_type
        variable end_type
        variable endtype_sel
        variable entry_end
        variable list_objs
	
	set entry_frame [frame $options_frame.entry_frame]
	set descp_frame [frame $options_frame.descp_frame]
        set left_frame [frame $options_frame.entry_frame.left_frame]
        set right_frame [frame $options_frame.entry_frame.right_frame]

        set start_frame [frame $options_frame.entry_frame.left_frame.start_frame]
        set objcl_frame [frame $options_frame.entry_frame.right_frame.objcl_frame]
        set bttns_frame [frame $options_frame.entry_frame.right_frame.bttns_frame]
        set ckbttn_frame [frame $options_frame.entry_frame.left_frame.ckbttn_frame]
        set sub1_frame [frame $options_frame.entry_frame.left_frame.ckbttn_frame.sub1_frame]
        set sub2_frame [frame $options_frame.entry_frame.left_frame.ckbttn_frame.sub2_frame]
        set attrib_frame [frame $options_frame.entry_frame.left_frame.attrib_frame]

	# Information Flow Entry frames
	set lbl_start_type [Label $entry_frame.left_frame.start_frame.lbl_start_type -text "Starting type:"]
    	set combo_start [ComboBox $entry_frame.left_frame.start_frame.combo_start -width 19 \
    		-helptext "You must choose a starting type for information flow"  \
    		-editable 1 \
    		-textvariable Apol_Analysis_iflow::start_type \
		-entrybg white]  
        set in_button [checkbutton $entry_frame.left_frame.ckbttn_frame.sub1_frame.in_button -text "In"]
        set out_button [checkbutton $entry_frame.left_frame.ckbttn_frame.sub1_frame.out_button -text "Out"]
        set either_button [checkbutton $entry_frame.left_frame.ckbttn_frame.sub2_frame.either_button -text "Either"]
        set both_button [checkbutton $entry_frame.left_frame.ckbttn_frame.sub2_frame.both_button -text "Both"]

        set cb_attrib [checkbutton $entry_frame.left_frame.attrib_frame.cb_attrib -text "Filter results by attrib:" \
		-variable Apol_Analysis_iflow::display_attrib_sel \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_iflow::config_attrib_comboBox_state }]

    	set combo_attribute [ComboBox $entry_frame.left_frame.attrib_frame.combo_attribute  \
    		-textvariable Apol_Analysis_iflow::display_attribute \
    		-modifycmd { Apol_Analysis_iflow::change_types_list}] 

      

        set clear_all_bttn [button $entry_frame.right_frame.bttns_frame.clear_all_bttn -text "Clear All:"]
        set select_all_bttn [button $entry_frame.right_frame.bttns_frame.select_all_bttn -text "Select All:"]

        set cb_endtype [checkbutton $entry_frame.left_frame.attrib_frame.cb_endtype -text "Filter results by endtype:" \
		-variable Apol_Analysis_iflow::endtype_sel \
		-offvalue 0 -onvalue 1 \
		-command { Apol_Analysis_iflow::config_endtype_state }]

        set entry_end [Entry $entry_frame.left_frame.attrib_frame.entry_end -width 19 \
		-helptext "You may choose an optional result type" \
		-editable 1 \
		-textvariable Apol_Analysis_iflow::end_type] 

        set cb_objects [checkbutton $entry_frame.right_frame.objcl_frame.cb_objects -text "Filter results by Object class:" \
		-variable Apol_Analysis_iflow::objects_sel \
		-offvalue 0 -onvalue 1 \
		-command {Apol_Analysis_iflow::config_objects_list_state }]

        set list_objs [listbox $entry_frame.right_frame.objcl_frame.list_objs \
		-height 7 \
		-width 20 \
		-yscrollcommand "$options_frame.entry_frame.right_frame.objcl_frame.scrl set"]

        set scrl [scrollbar $options_frame.entry_frame.right_frame.objcl_frame.scrl \
		-command "$options_frame.entry_frame.right_frame.objcl_frame.list_objs yview"]

	# Information Flow Analysis description frame
	set dLabel [Label $descp_frame.dLabel -text "Information Flow Analysis description:"]
    	set sw [ScrolledWindow $descp_frame.sw  -auto none]
	set descrp_text [text $sw.descrp_text -height 5 -width 20 -font {helvetica 10}  -wrap word]
	$sw setwidget $descrp_text
		
        # pack all the widgets
	pack $descp_frame -side right -fill both -expand yes -padx 10
	pack $entry_frame -side left -anchor nw -fill both -padx 10
        pack $left_frame  $right_frame -side left
        pack $start_frame $ckbttn_frame $attrib_frame -side top -anchor nw -fill both -pady 5
        pack $objcl_frame $bttns_frame -side top -padx 10
        pack $sub1_frame $sub2_frame -side left

        pack $cb_objects -side top -anchor nw
        pack $scrl -side right -fill y
        pack $list_objs -fill x

	pack $lbl_start_type -side top -anchor nw
        pack $combo_start -side left -anchor nw -fill x

        pack $in_button $out_button -side top -anchor nw
        pack $either_button $both_button -side top -anchor nw

        pack $cb_attrib -side top -anchor nw 
        pack $combo_attribute -side top -anchor nw -fill x
        pack $cb_endtype -side top -anchor nw
        pack $entry_end -side top -anchor nw -fill x

        pack $select_all_bttn -side left -anchor sw
        pack $clear_all_bttn -side right

    	pack $dLabel  -side top -anchor nw 
	pack $sw -side top -anchor nw -expand yes -fill both 
	
	$descrp_text insert 0.0 $descriptive_text
	$descrp_text config -state disable
    	
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list. 
#	bindtags $combo_attribute.e [linsert [bindtags $combo_attribute.e] 3 attribs_list_Tag]
#	bind attribs_list_Tag <KeyPress> { Apol_Users::_create_popup $Apol_Analysis_dta::combo_attribute %W %K }
	
        Apol_Analysis_iflow::config_attrib_comboBox_state	    	    
        Apol_Analysis_iflow::config_endtype_state
        Apol_Analysis_iflow::config_objects_list_state
	return 0	
}

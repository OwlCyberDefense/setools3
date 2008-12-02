# Copyright (C) 2004 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets
#
# Author: <don.patterson@tresys.com>
#

##############################################################
# ::Apol_Cond_Bools
#  
# The Conditional Booleans tab namespace
##############################################################
namespace eval Apol_Cond_Bools {
	# Search options
	# search_opts(opt), where opt =
	# 	boolean  	the name of the boolean
	#	default_state  	display default state 
	#	curr_state  	display current state 
	variable search_opts 
	set search_opts(boolean)	""
	set search_opts(default_state)	1
	set search_opts(curr_state)	1
	
	# list variables
	variable cond_bools_list	""
	# array variables
	variable cond_bools_value_array
	variable cond_bools_dflt_value_array
	# other
	variable enable_bool_combo_box	0
	variable use_regEx 0
	
	# Global widgets
	variable resultsbox
	variable cond_bools_listbox
	variable bool_combo_box
	variable cb_RegExp
}

###############################################################
#  ::cond_bool_search_bools
#
proc Apol_Cond_Bools::cond_bool_search_bools {} {
	variable search_opts
	variable cond_bools_value_array
	variable cond_bools_dflt_value_array
	variable cond_bools_list
	variable resultsbox
	variable use_regEx
	
	if {[ApolTop::is_policy_open]} {
		set results ""
		set search_opts(boolean) [string trim $search_opts(boolean)]
		if {$Apol_Cond_Bools::enable_bool_combo_box && $search_opts(boolean) == ""} {
			tk_messageBox -icon error -type ok -title "Error" -message "No boolean variable provided!"
			return -1
		}
				
		if {$Apol_Cond_Bools::enable_bool_combo_box && !$use_regEx} {	
			# validate the boolean exists in the array
			if {![Apol_Cond_Bools::cond_bool_is_valid_boolean $search_opts(boolean)]} {
				tk_messageBox -icon error -type ok -title "Error" -message "Invalid boolean variable!"
				return -1
			}
			set results [append results "$search_opts(boolean)"]
			if {$search_opts(default_state)} {
				if {$cond_bools_dflt_value_array($search_opts(boolean))} {
					set results [append results "  Default State: True"]
				} else {
					set results [append results "  Default State: False"]
				}
			} 
			if {$search_opts(curr_state)} {
				if {$cond_bools_value_array($search_opts(boolean))} {
					set results [append results "  Current State: True"]
				} else {
					set results [append results "  Current State: False"]
				}
			}
			set results [append results "\n"]
		} else {
			foreach bool $cond_bools_list {
				if {$use_regEx} {
					set rt [catch {set match [regexp $search_opts(boolean) $bool]} err]
					if {$rt != 0} {
						tk_messageBox \
							-icon error \
							-type ok \
							-title "Error" \
							-message $err
						return -1
					}
					if {$match} {
						set results [append results "$bool"]
					} else {
						continue
					}
				} else {
					set results [append results "$bool"]
				}
				if {$search_opts(default_state)} {
					if {$cond_bools_dflt_value_array($bool)} {
						set results [append results "  Default State: True"]
					} else {
						set results [append results "  Default State: False"]
					}
				} 
				if {$search_opts(curr_state)} {
					if {$cond_bools_value_array($bool)} {
						set results [append results "  Current State: True"]
					} else {
						set results [append results "  Current State: False"]
					}
				}
				set results [append results "\n"]
			}
		}
	
		$resultsbox configure -state normal
		$resultsbox delete 0.0 end
		$resultsbox insert end $results
		ApolTop::makeTextBoxReadOnly $resultsbox 
	} else {
		tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
		return -1
	}
	
	return 0
}

# -----------------------------------------------------------------
#  Command Apol_Cond_Bools::enable_RegExpr
#
#  Description: It is also called when the user modifies the value 
#		of the ComboBox by selecting it in the listbox. 
# -----------------------------------------------------------------
proc Apol_Cond_Bools::enable_RegExpr { } {
	variable bool_combo_box
	
	# Check to see if the "Enable Regular Expressions" checkbutton is ON. If not, then return.
	if {$Apol_Cond_Bools::use_regEx} {
        	set Apol_Cond_Bools::search_opts(boolean) "^$Apol_Cond_Bools::search_opts(boolean)$"
		selection clear -displayof $bool_combo_box
        }
	focus -force .
		    			
   	return 0
}

###############################################################
#  ::cond_bool_is_valid_boolean
#
proc Apol_Cond_Bools::cond_bool_is_valid_boolean {boolean} {
	variable cond_bools_value_array
	
	set items [array names cond_bools_value_array]
	if {$items != ""} {
		foreach item $items {
			if {[string equal $boolean $item]} {
				return 1
			}
		}
	}
	
	return 0	
}

################################################################
#  ::cond_bool_reset_variables
#
proc Apol_Cond_Bools::cond_bool_reset_variables { } {
	variable search_opts 
	variable cond_bools_list
	variable enable_bool_combo_box	
	variable cond_bools_value_array
	variable cond_bools_dflt_value_array
	
	set search_opts(boolean)	""
	set search_opts(show_rules)	""
	set search_opts(default_state)	1
	set search_opts(curr_state)	1
	set cond_bools_list 		""
	set enable_bool_combo_box 	0
	# unset array variables
	array unset cond_bools_value_array
	array unset cond_bools_dflt_value_array
	
	return 0	
}

###############################################################
#  ::cond_bool_set_bool_values_to_policy_defaults
#
proc Apol_Cond_Bools::cond_bool_set_bool_values_to_policy_defaults {} {
	variable cond_bools_dflt_value_array
	variable cond_bools_value_array
	
	array set cond_bools_value_array [array get cond_bools_dflt_value_array]
				
	return 0	
} 

###############################################################
#  ::cond_bool_set_bool_value
#
proc Apol_Cond_Bools::cond_bool_set_bool_value {bool_name} {
	set rt [catch {apol_Cond_Bool_SetBoolValue \
		$bool_name \
		$Apol_Cond_Bools::cond_bools_value_array($bool_name)} err]	 
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}		
	return 0	
} 

################################################################
#  ::cond_bool_embed_buttons
#
proc Apol_Cond_Bools::cond_bool_embed_buttons {widget bool_name} {	
	set rb_frame [frame $widget.rb_frame:$bool_name -bd 0 -bg white]
	set rb_true  [radiobutton $rb_frame.rb_true:$bool_name -bg white \
		-variable Apol_Cond_Bools::cond_bools_value_array($bool_name) \
		-command "Apol_Cond_Bools::cond_bool_set_bool_value $bool_name" \
		-value 1 -highlightthickness 0 -text "True"]
	set rb_false [radiobutton $rb_frame.rb_false:$bool_name -bg white \
		-variable Apol_Cond_Bools::cond_bools_value_array($bool_name) \
		-command "Apol_Cond_Bools::cond_bool_set_bool_value $bool_name" \
		-value 0 -highlightthickness 0 -text "False"]
	
	pack $rb_frame -side left -anchor nw
	pack $rb_true $rb_false -side left -anchor nw -padx 2
			
	return $rb_frame	
} 

################################################################
#  ::cond_bool_init_state
#
proc Apol_Cond_Bools::cond_bool_init_state { } {
	Apol_Cond_Bools::cond_bool_change_comboBox_state \
		$Apol_Cond_Bools::enable_bool_combo_box
			
	return 0
}

################################################################
# ::cond_bool_remove_listbox_items
#  	- Method for remove all embedded check buttons.
# 
proc Apol_Cond_Bools::cond_bool_remove_listbox_items { } {   
	variable cond_bools_listbox

	foreach item [$cond_bools_listbox items] {
		set window [$cond_bools_listbox itemcget $item -window]
    		if { [winfo exists $window] } {
			destroy $window
		}
	}
	# Delete
	$cond_bools_listbox delete [$cond_bools_listbox items]
	return 0	
}

################################################################
#  ::cond_bool_insert_listbox_items
#
proc Apol_Cond_Bools::cond_bool_insert_listbox_items { } {
	variable cond_bools_listbox 
	variable cond_bools_list
	
	foreach bool_name $cond_bools_list {
		$cond_bools_listbox insert end $bool_name -text " - $bool_name" \
		 	 -window [Apol_Cond_Bools::cond_bool_embed_buttons \
		 	 	$Apol_Cond_Bools::cond_bools_listbox $bool_name]  
		  
	}

    	# Display updates immediately.
    	# Adjust the view so that no part of the canvas is off-screen to the left.
	$cond_bools_listbox configure -redraw 1
    	$cond_bools_listbox.c xview moveto 0			 	 
    	update idletasks
    	$cond_bools_listbox configure -padx [winfo reqwidth [$cond_bools_listbox itemcget [$cond_bools_listbox items 0] -window]]	
	return 0
} 

################################################################
#  ::cond_bool_initialize
#
proc Apol_Cond_Bools::cond_bool_initialize_vars { } {
	variable cond_bools_list
	variable cond_bools_value_array
	variable cond_bools_dflt_value_array
	
	set rt [catch {set cond_bools_list [apol_GetNames cond_bools]} err]
	if {$rt != 0} {
		return -code error $err
	}	
	set cond_bools_list [lsort $cond_bools_list] 	
	
	foreach bool_name $cond_bools_list {
		set rt [catch {set cond_bools_value_array($bool_name) [apol_Cond_Bool_GetBoolValue $bool_name]} err]
		if {$rt != 0} {
			return -code error $err
		}
		set cond_bools_dflt_value_array($bool_name) $cond_bools_value_array($bool_name)
	}
					 	 
	return 0
} 

################################################################
#  ::cond_bool_change_comboBox_state
#
proc Apol_Cond_Bools::cond_bool_change_comboBox_state {enable} {
	variable cb_RegExp

	ApolTop::change_comboBox_state \
		$Apol_Cond_Bools::enable_bool_combo_box \
		$Apol_Cond_Bools::bool_combo_box	
	if {$enable} {
		$cb_RegExp configure -state normal
	} else {
		$cb_RegExp configure -state disabled
		$cb_RegExp deselect
	}	
	return 0
}

################################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Cond_Bools::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Cond_Bools::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

################################################################
# ::set_Focus_to_Text
# 
proc Apol_Cond_Bools::set_Focus_to_Text {} {
	focus $Apol_Cond_Bools::resultsbox
	return 0
}

################################################################
#  ::open
#
proc Apol_Cond_Bools::open { } {
	set rt [catch {Apol_Cond_Bools::cond_bool_initialize_vars} err]
	if {$rt != 0} {
		return -code error $err
	}
	$Apol_Cond_Bools::bool_combo_box configure -values $Apol_Cond_Bools::cond_bools_list
	if {$Apol_Cond_Bools::cond_bools_list != ""} {
		Apol_Cond_Bools::cond_bool_insert_listbox_items
	}
	
	return 0
} 

################################################################
#  ::close
#
proc Apol_Cond_Bools::close { } {	
	Apol_Cond_Bools::cond_bool_reset_variables
	
	Apol_Cond_Bools::cond_bool_remove_listbox_items
	Apol_Cond_Bools::cond_bool_change_comboBox_state \
		$Apol_Cond_Bools::enable_bool_combo_box
	$Apol_Cond_Bools::resultsbox configure -state normal
	$Apol_Cond_Bools::resultsbox delete 0.0 end
	ApolTop::makeTextBoxReadOnly $Apol_Cond_Bools::resultsbox 
	
	return 0	
}

################################################################
#  ::free_call_back_procs
#
proc Apol_Cond_Bools::free_call_back_procs { } {
     
	return 0
}

################################################################
#  ::create
#
proc Apol_Cond_Bools::create {nb} {
	variable bool_combo_box
	variable cond_bools_listbox 
	variable resultsbox 
	variable cb_RegExp
	
	# Layout frames
	set frame [$nb insert end $ApolTop::cond_bools_tab -text "Booleans"]
	set topf  [frame $frame.topf]
	set pw1   [PanedWindow $topf.pw -side top]
	set pane  [$pw1 add ]
	set spane [$pw1 add -weight 5]
	set pw2   [PanedWindow $pane.pw -side left]
	set rpane [$pw2 add -weight 3]
	
	# Title frames
	set cond_bools_box [TitleFrame $rpane.cond_bools_box -text "Booleans"]
	set s_optionsbox   [TitleFrame $spane.obox -text "Search Options"]
	set rslts_frame	   [TitleFrame $spane.rbox -text "Search Results"]
	
	# Placing layout
	pack $topf -fill both -expand yes 
	pack $pw1 -fill both -expand yes
	pack $pw2 -fill both -expand yes
	
	# Placing title frames
	pack $s_optionsbox -padx 2 -fill both
	pack $cond_bools_box -padx 2 -side left -fill both -expand yes
	pack $rslts_frame -pady 2 -padx 2 -fill both -anchor n -side bottom -expand yes
	
	# Roles listbox widget
	set sw_r [ScrolledWindow [$cond_bools_box getframe].sw -auto both]
	set cond_bools_listbox [ListBox [$cond_bools_box getframe].cond_bools_listbox \
	          -relief sunken -borderwidth 2 -bg white  \
	          -selectmode none -deltay 25 \
	          -width 25 -highlightthickness 0 \
	          -redraw 0]
	$sw_r setwidget $cond_bools_listbox 
	
	set button_defaults [button [$cond_bools_box getframe].button_defaults \
		-text "Reset to policy defaults" \
		-command {Apol_Cond_Bools::cond_bool_set_bool_values_to_policy_defaults}]
	    	
	# Search options subframes
	set ofm [$s_optionsbox getframe]
	set l_innerFrame [LabelFrame $ofm.l_innerFrame]
	set c_innerFrame [LabelFrame $ofm.c_innerFrame]
	set buttons_f    [LabelFrame $ofm.buttons_f]
	
	set cb_bools_default_state [checkbutton $c_innerFrame.default_state \
		-variable Apol_Cond_Bools::search_opts(default_state) \
		-text "Show default state" \
		-onvalue 1 -offvalue 0]
	set cb_bools_curr_state [checkbutton $c_innerFrame.curr_state \
		-variable Apol_Cond_Bools::search_opts(curr_state) \
		-text "Show current state" \
		-onvalue 1 -offvalue 0]
    		
	set bool_combo_box [ComboBox [$l_innerFrame getframe].bool_combo_box \
		-textvariable Apol_Cond_Bools::search_opts(boolean) \
		-helptext "Type or select a boolean variable" \
		-entrybg $ApolTop::default_bg_color \
		-modifycmd {Apol_Cond_Bools::enable_RegExpr}]
	set cb_enable_bool_combo_box [checkbutton [$l_innerFrame getframe].cb_enable_bool_combo_box \
		-variable Apol_Cond_Bools::enable_bool_combo_box \
		-onvalue 1 -offvalue 0 -text "Search using boolean variable" \
		-command {Apol_Cond_Bools::cond_bool_change_comboBox_state \
			$Apol_Cond_Bools::enable_bool_combo_box}]
	# Checkbutton to Enable/Disable Regular Expressions option.
    	set cb_RegExp [checkbutton [$l_innerFrame getframe].cb_RegExp \
    		-text "Enable Regular Expressions" \
    		-variable Apol_Cond_Bools::use_regEx \
    		-onvalue 1 -offvalue 0]
    		
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list.
	bindtags $bool_combo_box.e [linsert [bindtags $bool_combo_box.e] 3 bool_vars_combo_box_Tag]
	bind bool_vars_combo_box_Tag <KeyPress> { ApolTop::_create_popup $Apol_Cond_Bools::bool_combo_box %W %K }
			
	# Action Buttons
	set ok_button [button [$buttons_f getframe].ok -text "Search for Booleans" -width 15 -command {Apol_Cond_Bools::cond_bool_search_bools}]
	#button $rfm.print -text Print -width 6 -command {ApolTop::unimplemented}
	
	# Display results window
	set sw_d [ScrolledWindow [$rslts_frame getframe].sw -auto none]
	set resultsbox [text [$sw_d getframe].text -bg white -wrap none -state disabled]
	$sw_d setwidget $resultsbox
	
	# Placing all widget items
	pack $button_defaults -side bottom -pady 2 -anchor center
	pack $ok_button -side top -anchor e -pady 5 -padx 5
	pack $buttons_f -side right -expand yes -fill both -anchor nw -padx 4 -pady 4
	pack $l_innerFrame $c_innerFrame -side left -fill y -anchor nw -padx 4 -pady 4
	
	pack $cb_enable_bool_combo_box $bool_combo_box -side top -anchor nw -fill x
	pack $cb_RegExp -side top -anchor nw 
	pack $cb_bools_default_state $cb_bools_curr_state -side top -anchor nw 
	pack $sw_r -fill both -expand yes
	pack $sw_d -side left -expand yes -fill both 
	Apol_Cond_Bools::cond_bool_init_state
	
	return $frame	
}


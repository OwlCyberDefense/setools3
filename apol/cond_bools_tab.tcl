# Copyright (C) 2004-2005 Tresys Technology, LLC
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
                $resultsbox insert end "BOOLEANS:\n"
                if {$results == ""} {
                        $resultsbox insert end "Search returned no results."
                } else {
                        $resultsbox insert end $results
                }
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

    foreach w [winfo children [$cond_bools_listbox getframe]] {
        catch {destroy $w}
    }
    # get rid of the scrollbars
    [$cond_bools_listbox getframe] configure -width 1 -height 1
}

################################################################
#  ::cond_bool_insert_listbox_items
#
proc Apol_Cond_Bools::cond_bool_insert_listbox_items { } {
    variable cond_bools_listbox 
    variable cond_bools_list

    set subf [$cond_bools_listbox getframe]
    $subf configure -width 0 -height 0
    foreach bool_name $cond_bools_list {
        set rb_true [radiobutton $subf.rb_true:$bool_name -bg white \
                         -variable Apol_Cond_Bools::cond_bools_value_array($bool_name) \
                         -command [list Apol_Cond_Bools::cond_bool_set_bool_value $bool_name] \
                         -value 1 -highlightthickness 0 -text "True"]
        set rb_false [radiobutton $subf.rb_false:$bool_name -bg white \
                          -variable Apol_Cond_Bools::cond_bools_value_array($bool_name) \
                          -command [list Apol_Cond_Bools::cond_bool_set_bool_value $bool_name] \
                          -value 0 -highlightthickness 0 -text "False"]
        set rb_label [label $subf.rb_label:$bool_name \
                          -bg white -text "- $bool_name"]
        grid $rb_true $rb_false $rb_label -padx 2 -pady 5 -sticky w
    }
    $cond_bools_listbox configure -areaheight 0 -areawidth 0
    $cond_bools_listbox xview moveto 0
    $cond_bools_listbox yview moveto 0
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
        set pw [PanedWindow $frame.pw -side top]
        set left_pane [$pw add -weight 0]
        set right_pane [$pw add -weight 1]
        pack $pw -expand 1 -fill both

	# Title frames
	set cond_bools_box [TitleFrame $left_pane.cond_bools_box -text "Booleans"]
	set s_optionsbox   [TitleFrame $right_pane.obox -text "Search Options"]
	set rslts_frame	   [TitleFrame $right_pane.rbox -text "Search Results"]
	pack $cond_bools_box -padx 2 -expand 1 -fill both
	pack $s_optionsbox -padx 2 -fill x -expand 0 -side top
	pack $rslts_frame -pady 2 -padx 2 -fill both -side bottom -expand yes

	# Booleans listbox widget
        set left_frame [$cond_bools_box getframe]
        set sw_b [ScrolledWindow $left_frame.sw -auto both]
        set cond_bools_listbox [ScrollableFrame $sw_b.cond_bools_listbox -bg white -width 200]
        set subf [$cond_bools_listbox getframe]
	$sw_b setwidget $cond_bools_listbox
	set button_defaults [button $left_frame.button_defaults \
		-text "Reset to policy defaults" \
		-command {Apol_Cond_Bools::cond_bool_set_bool_values_to_policy_defaults}]
        pack $sw_b -side top -expand 1 -fill both
        pack $button_defaults -side bottom -expand 0 -fill x

	# Search options subframes
	set ofm [$s_optionsbox getframe]
	set l_innerFrame [LabelFrame $ofm.l_innerFrame]
	set c_innerFrame [LabelFrame $ofm.c_innerFrame]
	
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
	set ok_button [button $ofm.ok -text "OK" -width 6 \
                           -command Apol_Cond_Bools::cond_bool_search_bools]
	
	# Display results window
	set sw_d [ScrolledWindow [$rslts_frame getframe].sw -auto none]
	set resultsbox [text [$sw_d getframe].text -bg white -wrap none -state disabled]
	$sw_d setwidget $resultsbox
	
	# Placing all widget items
	pack $button_defaults -side bottom -pady 2 -anchor center
	pack $ok_button -side right -anchor ne -padx 5 -pady 5
	pack $l_innerFrame $c_innerFrame -side left -fill y -anchor nw -padx 4 -pady 4
	
	pack $cb_enable_bool_combo_box $bool_combo_box -side top -anchor nw -fill x
	pack $cb_RegExp -side top -anchor nw 
	pack $cb_bools_default_state $cb_bools_curr_state -side top -anchor nw 
	pack $sw_d -side left -expand yes -fill both 
	Apol_Cond_Bools::cond_bool_init_state
	
	return $frame	
}


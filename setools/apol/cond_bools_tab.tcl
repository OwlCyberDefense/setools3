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
	variable resultsbox
	variable cond_bools_listbox 
	variable cond_bools_list
	variable cond_bools_value_array
	
	# callback procedures for the listbox items menu. Each element in this list is an embedded list of 2 items.
 	# The 2 items consist of the command label and the function name. The tabname will be added as an
 	# argument to the callback procedure.
	variable menu_callbacks		""
	
}

########################################################################
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

########################################################################
#  ::cond_bool_embed_checkbutton
#
proc Apol_Cond_Bools::cond_bool_embed_checkbutton {bool_name} {
	variable cond_bools_listbox
	
	set cb_name [checkbutton $cond_bools_listbox.$bool_name -bg white \
		-onvalue 1 -offvalue 0 \
		-variable Apol_Cond_Bools::cond_bools_value_array($bool_name) \
		-command "Apol_Cond_Bools::cond_bool_set_bool_value $bool_name"]
		
	return $cb_name	
} 

########################################################################
#  ::cond_bool_insert_listbox_items
#
proc Apol_Cond_Bools::cond_bool_insert_listbox_items { } {
	variable cond_bools_listbox 
	variable cond_bools_list
	
	foreach bool_name $cond_bools_list {
		# Insert item into listbox and a checkbox at the left of the label of the item.
		$cond_bools_listbox insert end $bool_name -text $bool_name \
		 	 -window [Apol_Cond_Bools::cond_bool_embed_checkbutton $bool_name]  	
	}
	# Adjust the view so that no part of the canvas is off-screen to the left.
    	# Finally, we display updates immediately.
	$cond_bools_listbox configure -redraw 1
    	$cond_bools_listbox.c xview moveto 0
    				 	 
	return 0
} 

########################################################################
#  ::cond_bool_initialize
#
proc Apol_Cond_Bools::cond_bool_initialize_vars { } {
	variable cond_bools_list
	variable cond_bools_value_array
	
	set cond_bools_list [apol_GetNames cond_bools]
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
	}
				 	 
	return 0
} 

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Cond_Bools::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Cond_Bools::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

########################################################################
# ::set_Focus_to_Text
# 
proc Apol_Cond_Bools::set_Focus_to_Text {} {
	focus $Apol_Cond_Bools::resultsbox
	return 0
}

########################################################################
#  ::open
#
proc Apol_Cond_Bools::open { } {
	set rt [catch {Apol_Cond_Bools::cond_bool_initialize_vars} err]
	if {$rt != 0} {
		return -code error $err
	}
	Apol_Cond_Bools::cond_bool_insert_listbox_items			 	 
	return 0
} 

########################################################################
#  ::close
#
proc Apol_Cond_Bools::close { } {
	set cond_bools_list ""
	return 0	
}

proc Apol_Cond_Bools::free_call_back_procs { } {
       	variable menu_callbacks	
    		
	set menu_callbacks ""
	return 0
}

########################################################################
#  ::create
#
proc Apol_Cond_Bools::create {nb} {
	variable cond_bools_listbox 
	variable resultsbox 
	variable menu_callbacks
	
	# Layout frames
	set frame [$nb insert end $ApolTop::cond_bools_tab -text "Conditional Booleans"]
	set topf  [frame $frame.topf]
	set pw1   [PanedWindow $topf.pw -side top]
	set pane  [$pw1 add ]
	set spane [$pw1 add -weight 5]
	set pw2   [PanedWindow $pane.pw -side left]
	set rpane [$pw2 add -weight 3]
	
	# Title frames
	set cond_bools_box 	 [TitleFrame $rpane.cond_bools_box -text "Booleans"]
	set s_optionsbox [TitleFrame $spane.obox -text "Search Options"]
	set rslts_frame	 [TitleFrame $spane.rbox -text "Search Results"]
	
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
	#set cond_bools_listbox [listbox [$sw_r getframe].lb -height 18 -width 20 -highlightthickness 0 \
	#	 -listvar Apol_Cond_Bools::cond_bools_list -bg white] 
	set cond_bools_listbox [ListBox [$sw_r getframe].lb \
		-height 18 -width 20 \
		-relief sunken -borderwidth 1 \
		-bg white \
	        -selectmode single -deltay 25 \
	        -highlightthickness 0 \
	        -redraw 0 -padx 30]
	$sw_r setwidget $cond_bools_listbox 
	    
	# Popup menu widget
	menu .popupMenu_bools
	set menu_callbacks [lappend menu_callbacks {"Display Boolean Info" "Apol_Cond_Bools::popup_cond_boolean_info"}]
	    
	# Event binding on the users list box widget
	bindtags $cond_bools_listbox [linsert [bindtags $cond_bools_listbox] 3 boolslist_Tag]  
	bind boolslist_Tag <Double-Button-1> {Apol_Cond_Bools::popup_cond_boolean_info [$Apol_Cond_Bools::cond_bools_listbox get active]}
	bind boolslist_Tag <Button-3> {ApolTop::popup_listbox_Menu \
		%W %x %y .popupMenu_bools $Apol_Cond_Bools::menu_callbacks \
		$Apol_Cond_Bools::cond_bools_listbox}
	bind boolslist_Tag <<ListboxSelect>> {focus -force $Apol_Cond_Bools::cond_bools_listbox}
	
	# Search options subframes
	set ofm [$s_optionsbox getframe]
	set buttons_f    [LabelFrame $ofm.buttons_f]
	# Action Buttons
	set ok_button [button [$buttons_f getframe].ok -text OK -width 6 -command {ApolTop::unimplemented}]
	#button $rfm.print -text Print -width 6 -command {ApolTop::unimplemented}
	
	# Display results window
	set sw_d [ScrolledWindow [$rslts_frame getframe].sw -auto none]
	set resultsbox [text [$sw_d getframe].text -bg white -wrap none -state disabled]
	$sw_d setwidget $resultsbox
	
	# Placing all widget items
	pack $ok_button -side top -anchor e -pady 5 -padx 5
	pack $buttons_f -side right -expand yes -fill both -anchor nw -padx 4 -pady 4
	
	pack $sw_r -fill both -expand yes
	pack $sw_d -side left -expand yes -fill both 
	
	return $frame	
}


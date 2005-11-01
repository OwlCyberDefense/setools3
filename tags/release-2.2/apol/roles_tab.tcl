# Copyright (C) 2001-2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets


##############################################################
# ::Apol_Roles
#  
# The Roles page
##############################################################
namespace eval Apol_Roles {
# opts(opt), where opt =
# roles          use roles

	variable opts
	set opts(roles)			1
	set opts(useType)		0
	set opts(showSelection)         all
	variable srchstr 		""
	variable role_list 		""
	variable types_list 		""
	variable selected_attribute	""
	variable attrib_sel		0
		
	# Global Widgets
	variable resultsbox
	variable rlistbox
	variable combo_types
	variable combo_attribute
	variable cb_attrib
	variable cb_type
	
	# callback procedures for the listbox items menu. Each element in this list is an embedded list of 2 items.
	# The 2 items consist of the command label and the function name. The tabname will be added as an
	# argument to the callback procedure.
	variable menu_callbacks		""
}

proc Apol_Roles::open { } {
	variable role_list
    
        set rt [catch {set role_list [apol_GetNames roles]} err]
        if {$rt != 0} {
		return -code error $err
	}
	set role_list [lsort $role_list]
	Apol_Roles::enable_type_list
        $Apol_Roles::combo_types configure -values $Apol_Types::typelist
        $Apol_Roles::combo_attribute configure -values $Apol_Types::attriblist
        return 0
}

proc Apol_Roles::close { } {
	variable opts 
	variable combo_types
	variable combo_attribute
	variable cb_attrib
	variable cb_type
	
	set opts(roles)		1
	set opts(useType)	0
	set Apol_Roles::attrib_sel	0
	set opts(showSelection) 	all
	set Apol_Roles::srchstr 	""
	set Apol_Roles::role_list 	""
	set Apol_Roles::types_list 	""
	set Apol_Roles::selected_attribute	""
	set Apol_Roles::role_list 	""
        $Apol_Roles::combo_types configure -values ""
        $Apol_Roles::combo_attribute configure -values ""
        $Apol_Roles::resultsbox configure -state normal
        $Apol_Roles::resultsbox delete 0.0 end
        ApolTop::makeTextBoxReadOnly $Apol_Roles::resultsbox 
        set Apol_Roles::types_list ""
       	Apol_Roles::enable_type_list
	return	
}

proc Apol_Roles::free_call_back_procs { } {
       	variable menu_callbacks	
    		
	set menu_callbacks ""
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Roles::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_Roles::set_Focus_to_Text {} {
	focus $Apol_Roles::resultsbox
	return 0
}

proc Apol_Roles::popupRoleInfo {which role} {
	set rt [catch {set info [apol_GetSingleRoleInfo $role 1]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}

	set w .role_infobox
	set rt [catch {destroy $w} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}
	toplevel $w 
	wm title $w "$role"
	wm protocol $w WM_DELETE_WINDOW " "
    	wm withdraw $w
	set sf [ScrolledWindow $w.sf  -scrollbar both -auto both]
	set f [text [$sf getframe].f -font {helvetica 10} -wrap none -width 35 -height 10]
	$sf setwidget $f
     	set b1 [button $w.close -text Close -command "catch {destroy $w}" -width 10]
     	pack $b1 -side bottom -anchor s -padx 5 -pady 5 
	pack $sf -fill both -expand yes
     	$f insert 0.0 $info
 	wm geometry $w +50+50
 	wm deiconify $w
 	$f configure -state disabled
 	wm protocol $w WM_DELETE_WINDOW "destroy $w"
	return 0
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Roles::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

proc Apol_Roles::searchRoles {} {
	variable opts
	variable resultsbox

	if {$opts(showSelection) == "names"} {
		set name_only 1
	} else {
		set name_only 0
	}
        set rt [catch {set results [apol_GetRolesByType $name_only $opts(useType) \
		$Apol_Roles::types_list]} err]
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return 
	} else {
	    $resultsbox configure -state normal
	    $resultsbox delete 0.0 end
	    $resultsbox insert end $results
	    ApolTop::makeTextBoxReadOnly $resultsbox 
        }
	
	return
}

proc Apol_Roles::enable_attrib_list {combo_box cb_value} {
	if {$cb_value} {
		$combo_box configure -state normal -entrybg white
	} else {
		$combo_box configure -state disabled -entrybg $ApolTop::default_bg_color
	}
	Apol_Roles::change_types_list
	return 0
}

proc Apol_Roles::enable_type_list {} {
	variable combo_types
	variable combo_attribute
	variable attrib_sel
	variable cb_attrib
	variable opts
	
	if {$opts(useType)} {
		$combo_types configure -state normal -entrybg white
		$cb_attrib configure -state normal
		if {$attrib_sel} {
			$combo_attribute configure -state normal -entrybg white
		} else {
			$combo_attribute configure -state disabled -entrybg $ApolTop::default_bg_color
		}
		Apol_Roles::change_types_list
	} else {
		$combo_types configure -state disabled -entrybg  $ApolTop::default_bg_color
		$combo_attribute configure -state disabled -entrybg  $ApolTop::default_bg_color
		$cb_attrib configure -state disabled
		$cb_attrib deselect
	}
	
	return 0
}

proc Apol_Roles::change_types_list { } { 
	variable selected_attribute	
	variable combo_types
	variable attrib_sel
	
	if {$attrib_sel && $selected_attribute != ""} {	   
		set rt [catch {set attrib_typesList [apol_GetAttribTypesList $selected_attribute]} err]	
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message "$err"
			return -1
		} 
		set attrib_typesList [lsort $attrib_typesList]
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
		$combo_types configure -values $attrib_typesList
        } else {
        	set attrib_typesList $Apol_Types::typelist
		set idx [lsearch -exact $attrib_typesList "self"]
		if {$idx != -1} {
			set attrib_typesList [lreplace $attrib_typesList $idx $idx]
		}
        	$combo_types configure -values $attrib_typesList
        }
        selection clear -displayof $combo_types
     	return 0
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Roles::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

proc Apol_Roles::create {nb} {
	variable rlistbox 
	variable resultsbox 
	variable srchstr 
	variable opts
	variable types_list
	variable combo_types
	variable combo_attribute
	variable cb_attrib
	variable cb_type
	variable menu_callbacks
	
	# Layout frames
	set frame [$nb insert end $ApolTop::roles_tab -text "Roles"]
	set topf  [frame $frame.topf]
	set pw1   [PanedWindow $topf.pw -side top]
	set pane  [$pw1 add ]
	set spane [$pw1 add -weight 5]
	set pw2   [PanedWindow $pane.pw -side left]
	set rpane [$pw2 add -weight 3]
	
	# Title frames
	set rolebox [TitleFrame $rpane.rolebox -text "Roles"]
	set s_optionsbox [TitleFrame $spane.obox -text "Search Options"]
	set resultsbox [TitleFrame $spane.rbox -text "Search Results"]
	
	# Placing layout
	pack $topf -fill both -expand yes 
	pack $pw1 -fill both -expand yes
	pack $pw2 -fill both -expand yes
	
	# Placing title frames
	pack $s_optionsbox -padx 2 -fill both
	pack $rolebox -padx 2 -side left -fill both -expand yes
	pack $resultsbox -pady 2 -padx 2 -fill both -anchor n -side bottom -expand yes
	
	# Roles listbox widget
	set sw_r [ScrolledWindow [$rolebox getframe].sw -auto both]
	set rlistbox [listbox [$sw_r getframe].lb -height 18 -width 20 -highlightthickness 0 \
		 -listvar Apol_Roles::role_list -bg white] 
	$sw_r setwidget $rlistbox 
	
	# Popup menu widget
	menu .popupMenu_roles
	set menu_callbacks [lappend menu_callbacks {"Display Role Info" "Apol_Roles::popupRoleInfo role"}]
		    
	# Event bindong on the roles list box widget
	bindtags $rlistbox [linsert [bindtags $rlistbox] 3 rlist_Tag]  
	bind rlist_Tag <Double-Button-1> { Apol_Roles::popupRoleInfo "role" [$Apol_Roles::rlistbox get active]}
	bind rlist_Tag <Button-3> { ApolTop::popup_listbox_Menu \
		%W %x %y .popupMenu_roles $Apol_Roles::menu_callbacks \
		$Apol_Roles::rlistbox}
	bind rlist_Tag <<ListboxSelect>> { focus -force $Apol_Roles::rlistbox}
	
	# Search options subframes
	set ofm [$s_optionsbox getframe]
	set l_innerFrame [LabelFrame $ofm.to \
	            -relief sunken -borderwidth 1]
	set c_innerFrame [LabelFrame $ofm.co \
	            -relief sunken -borderwidth 1]
	set r_innerFrame [frame $ofm.ro \
	            -relief flat -borderwidth 1]
	
	# Placing inner frames
	set lfm [$l_innerFrame getframe]
	set cfm [$c_innerFrame getframe]
	set rfm  $r_innerFrame
	
	# Search options widget items
	set combo_types [ComboBox $cfm.combo_types -width 30 -textvariable Apol_Roles::types_list \
		  -helptext "Type or select a type"]
		
	set cb_type [checkbutton $cfm.cb -variable Apol_Roles::opts(useType) -text "Search Using Type" \
			-command {Apol_Roles::enable_type_list}]
		
	# ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
	# If bindtags is invoked with only one argument, then the current set of binding tags for window is 
	# returned as a list.
	bindtags $combo_types.e [linsert [bindtags $combo_types.e] 3 listTag]
	bind listTag <KeyPress> { ApolTop::_create_popup $Apol_Roles::combo_types %W %K }
	
	set combo_attribute [ComboBox $cfm.combo_attribute  \
		-textvariable Apol_Roles::selected_attribute \
		-modifycmd {Apol_Roles::change_types_list} \
		-exportselection 0] 
		
	set cb_attrib [checkbutton $cfm.cb_attrib -text "Filter types to select using attribute:" \
		-variable Apol_Roles::attrib_sel \
		-offvalue 0 -onvalue 1 \
		-command {Apol_Roles::enable_attrib_list $Apol_Roles::combo_attribute $Apol_Roles::attrib_sel}]
		
	# Set default state for combo boxes
	Apol_Roles::enable_type_list	
	radiobutton $lfm.names_only -text "Names Only" -variable Apol_Roles::opts(showSelection) -value names 
	radiobutton $lfm.all_info -text "All Information" -variable Apol_Roles::opts(showSelection) -value all 
		
	# Action Buttons
	button $rfm.ok -text OK -width 6 -command {Apol_Roles::searchRoles}      
	#button $rfm.print -text Print -width 6 -command {ApolTop::unimplemented}
	
	# Display results window
	set sw_d [ScrolledWindow [$resultsbox getframe].sw -auto none]
	set resultsbox [text [$sw_d getframe].text -bg white -wrap none -state disabled]
	$sw_d setwidget $resultsbox
	
	# Placing all widget items
	pack $r_innerFrame -side right -fill both -expand yes -anchor ne
	pack $l_innerFrame -side left -fill both -anchor n
	pack $c_innerFrame -side right -expand yes -anchor nw -padx 5
	pack $rfm.ok -side top -anchor e -pady 5 -padx 5
	pack $lfm.names_only $lfm.all_info -side top -anchor nw -pady 5 -padx 5
	pack $cb_type -side top -anchor nw -padx 10 
	pack $combo_types -anchor w -padx 10
	pack $cb_attrib -expand yes -anchor nw -padx 15
	pack $combo_attribute -fill x -expand yes -padx 25
	pack $sw_r -fill both -expand yes
	pack $sw_d -side left -expand yes -fill both 
	
	return $frame	
}


# Copyright (C) 2001-2005 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets


##############################################################
# ::Apol_RBAC
#  
# The Access Control Rules page
##############################################################
namespace eval Apol_RBAC {
# opts(opt), where opt =
# allow                 rule selection
# transition            rule selection
# use_src_list          whether to use source role
# use_tgt_list          whether to use target (role, type, or attrib)
# use_dflt_list         whether to use default role
# list_type             variable for radiobuttons to indicate whether the type is role, type, or attrib 
# which_1               indicates whether src_roles is used for source, or any location
# src_role		source role 
# tgt_selection		target role/type/attrib
# dflt_role             default role

	variable opts
	set opts(allow)                 1
	set opts(transition)            0
	set opts(use_src_list)		0
	set opts(use_tgt_list)          0
	set opts(use_dflt_list)         0
	set opts(list_type)	        types
	set opts(which_1)	        source
	variable src_role ""
	variable tgt_selection ""
	variable dflt_role ""

	# Global Widgets
	variable list_src
	variable list_tgt
	variable list_dflt_role
	variable global_asSource
	variable global_any
	variable list_types 
	variable list_attribs 
	variable list_roles
	variable use_src_list
	variable use_dflt_role
	variable use_tgt_list
	variable resultsbox
	
	# Interactive Label Messages
	variable m_use_tgt_role        "Target Role"
	variable m_use_tgt_ta          "Target Type/Attrib"
	variable m_disable_tgt         "Target"
	variable m_disable_dflt_role   "Default Role"
	variable m_use_dflt_role       "Default Role"
	variable m_use_src_role        "Source Role"
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_RBAC::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_RBAC::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_RBAC::set_Focus_to_Text {} {
	focus $Apol_RBAC::resultsbox
	return 0
}

proc Apol_RBAC::searchRoles {} {
	variable opts
	variable resultsbox
        variable src_role
        variable tgt_selection
        variable list_dflt_role
		
        if {$opts(list_type) == "roles"} {
		set tgt_is_role 1
	} else {
		set tgt_is_role 0 
	}

        set rt [catch {set results [apol_GetRoleRules $opts(allow) $opts(transition) \
                $opts(use_src_list) $Apol_RBAC::src_role  $opts(which_1) \
		$opts(use_tgt_list) $Apol_RBAC::tgt_selection $tgt_is_role \
		$opts(use_dflt_list) $Apol_RBAC::dflt_role]} err]
        if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return 
	} else {
	    	$resultsbox configure -state normal
		$resultsbox delete 0.0 end
		$resultsbox insert end $results
		ApolTop::makeTextBoxReadOnly $resultsbox 
        }
	

}

proc Apol_RBAC::open { } {
	variable opts
	
	$Apol_RBAC::list_src configure -values $Apol_Roles::role_list
	$Apol_RBAC::list_tgt configure -values $Apol_Types::typelist
        $Apol_RBAC::list_dflt_role configure -values $Apol_Roles::role_list
        return 0
}

proc Apol_RBAC::close { } {
	Apol_RBAC::init_options
	$Apol_RBAC::list_src configure -values ""
	$Apol_RBAC::list_tgt configure -values ""
        $Apol_RBAC::list_dflt_role configure -values ""
        $Apol_RBAC::resultsbox configure -state normal
	$Apol_RBAC::resultsbox delete 0.0 end
	ApolTop::makeTextBoxReadOnly $Apol_RBAC::resultsbox 

	return	
}

proc Apol_RBAC::free_call_back_procs { } {
  
	return 0
}

proc Apol_RBAC::init_options { } {
	variable list_src
	variable list_tgt
	variable list_dflt_role
	variable opts
	set opts(allow)                 1
	set opts(transition)            0
	set opts(use_src_list)		0
	set opts(use_tgt_list)          0
	set opts(use_dflt_list)         0
	set opts(list_type)	        types
	set opts(which_1)	        source
	set Apol_RBAC::src_role ""
	set Apol_RBAC::tgt_selection ""
        set Apol_RBAC::dflt_role ""
        
        Apol_RBAC::enable_disable_tgt
        Apol_RBAC::enable_disable_tgt_dflt_sections
        Apol_RBAC::useSearch $list_src 1
        Apol_RBAC::useSearch $list_tgt 2
        Apol_RBAC::useSearch $list_dflt_role 3
        
        return
}


proc Apol_RBAC::useSearch { entry list_number } {
    variable global_asSource
    variable global_any
    variable list_types 
    variable list_attribs 
    variable list_both

    if { $list_number == 1 } {
	set which list1
    } elseif {$list_number == 2} {
	set which list2
    } elseif {$list_number == 3} {
	set which list3
    } else {
	return -code error
    }
    switch $which {
	list1 {
	    if { $Apol_RBAC::opts(use_src_list) } {
		if { $Apol_RBAC::opts(which_1) == "source"} {
		    $entry configure -state normal   -entrybg white
		    $Apol_RBAC::global_asSource configure -state normal
		    $Apol_RBAC::global_any configure -state normal
		} else {
		    $entry configure -state normal -entrybg  white
		    $Apol_RBAC::global_asSource configure -state normal
		    $Apol_RBAC::global_any configure -state normal	
		    Apol_RBAC::enable_disable_tgt_dflt_sections
		}
	    } else { 
		$entry configure -state disabled  -entrybg  $ApolTop::default_bg_color
		$Apol_RBAC::global_asSource configure -state disabled
		$Apol_RBAC::global_any configure -state disabled
		Apol_RBAC::enable_disable_tgt_dflt_sections
	    }
	}
	list2 {
	    if { $Apol_RBAC::opts(use_tgt_list) } {
		if { $Apol_RBAC::opts(allow) } {
		    $entry configure -state normal   -entrybg white
		    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_use_tgt_role \
			-state normal
		    $Apol_RBAC::list_types configure -state disabled
		    $Apol_RBAC::list_attribs configure -state disabled
		    $Apol_RBAC::list_roles configure -state normal
		    $Apol_RBAC::list_roles invoke
		} elseif { $Apol_RBAC::opts(transition) } {
		    $entry configure -state normal   -entrybg  white
		    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_use_tgt_ta \
			-state normal
		    $Apol_RBAC::list_roles configure -state disabled
		    $Apol_RBAC::list_attribs configure -state normal
		    $Apol_RBAC::list_types configure -state normal
		    $Apol_RBAC::list_types invoke
		} else {
		    $entry configure -state normal   -entrybg white
		    $Apol_RBAC::list_types configure -state normal
		    $Apol_RBAC::list_attribs configure -state normal
		    $Apol_RBAC::list_roles configure -state normal
		}
	    } else {
		$entry configure -state disabled   -entrybg  $ApolTop::default_bg_color
		$Apol_RBAC::list_types configure -state disabled
		$Apol_RBAC::list_attribs configure -state disabled
		$Apol_RBAC::list_roles configure -state disabled
	    }
	}
	list3 {
	    if { $Apol_RBAC::opts(use_dflt_list) } {
		$entry configure -state normal   -entrybg white
	    } else {
		$entry configure -state disabled  -entrybg  $ApolTop::default_bg_color
	    }
	}
	default {
			return -code error
		}
    }
    return 0
}

proc Apol_RBAC::enable_disable_tgt { } {
    variable opts
    variable list_tgt
    variable list_types 
    variable list_attribs 
    variable list_roles
    variable use_tgt_list
    
    if { $Apol_RBAC::opts(use_tgt_list) } {
	if { $Apol_RBAC::opts(allow) && $Apol_RBAC::opts(transition) } {
	    $Apol_RBAC::use_tgt_list deselect
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::list_types configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_disable_tgt -state disabled
	    $Apol_RBAC::use_dflt_role configure -state disabled \
		-text $Apol_RBAC::m_disable_dflt_role
	    $Apol_RBAC::use_dflt_role deselect
	} elseif { $Apol_RBAC::opts(allow) } {
	    $Apol_RBAC::use_tgt_list deselect
	    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_use_tgt_role -state normal
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::list_types configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	    $Apol_RBAC::list_dflt_role configure -state disabled
	    $Apol_RBAC::use_dflt_role configure -state disabled \
		-text  $Apol_RBAC::m_disable_dflt_role
	    $Apol_RBAC::use_dflt_role deselect
	} elseif { $Apol_RBAC::opts(transition) } {
	    $Apol_RBAC::use_tgt_list deselect
	    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_use_tgt_ta -state normal
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_types configure -state disabled
	} else {
	    $Apol_RBAC::use_tgt_list deselect
	    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_disable_tgt -state disabled
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_types configure -state disabled
	    $Apol_RBAC::use_dflt_role configure -state disabled \
		-text $Apol_RBAC::m_disable_dflt_role
	    $Apol_RBAC::use_dflt_role deselect
	}
    } else {
	if { $Apol_RBAC::opts(allow) && $Apol_RBAC::opts(transition) } {
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::list_types configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_disable_tgt -state disabled
	    $Apol_RBAC::use_dflt_role configure -state disabled \
		-text $Apol_RBAC::m_disable_dflt_role
	    $Apol_RBAC::use_dflt_role deselect
	} elseif { $Apol_RBAC::opts(allow) } {
	    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_use_tgt_role -state normal
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::list_types configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	    $Apol_RBAC::list_dflt_role configure -state disabled
	    $Apol_RBAC::use_dflt_role configure -state disabled \
		-text $Apol_RBAC::m_disable_dflt_role
	    $Apol_RBAC::use_dflt_role deselect
	} elseif { $Apol_RBAC::opts(transition) } {
	    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_use_tgt_ta -state normal
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_types configure -state disabled
   	} else {
	    $Apol_RBAC::use_tgt_list configure -text $Apol_RBAC::m_disable_tgt -state disabled
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_types configure -state disabled
	    $Apol_RBAC::use_dflt_role configure -state disabled \
		-text $Apol_RBAC::m_disable_dflt_role
	    $Apol_RBAC::use_dflt_role deselect
	}
    }   
}

proc Apol_RBAC::enable_disable_tgt_dflt_sections { } {
    variable list_tgt
    variable list_dflt_role
    variable list_types 
    variable list_attribs 
    variable list_roles
    variable use_dflt_role
    variable use_tgt_list

     if { $Apol_RBAC::opts(use_src_list) == 1 } {
	if { $Apol_RBAC::opts(which_1) == "any" } {
	    $Apol_RBAC::list_dflt_role configure -state disabled
	    $Apol_RBAC::use_dflt_role configure -state disabled \
		-text $Apol_RBAC::m_disable_dflt_role
	    $Apol_RBAC::use_dflt_role deselect
	    $Apol_RBAC::list_tgt configure -state disabled
	    $Apol_RBAC::use_tgt_list configure -state disabled -text $Apol_RBAC::m_disable_tgt
	    $Apol_RBAC::use_tgt_list deselect
	    $Apol_RBAC::list_types configure -state disabled
	    $Apol_RBAC::list_attribs configure -state disabled
	    $Apol_RBAC::list_roles configure -state disabled
	} elseif { $Apol_RBAC::opts(which_1) == "source" } {
	    $Apol_RBAC::use_dflt_role configure -state normal \
		-text $Apol_RBAC::m_use_dflt_role
	    Apol_RBAC::enable_disable_tgt
	}
     } else {
	 $Apol_RBAC::use_dflt_role configure -state normal -text $Apol_RBAC::m_use_dflt_role
	 Apol_RBAC::enable_disable_tgt
     }
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_RBAC::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_RBAC::populate_listbox
# ------------------------------------------------------------------------------
proc Apol_RBAC::populate_listbox { cBox } {
	$cBox configure -text ""		
	switch $Apol_RBAC::opts(list_type) {
		types {
			$cBox configure -values $Apol_Types::typelist
		}
		attribs {
			$cBox configure -values $Apol_Types::attriblist
		}
		both {
			set bothlist [concat $Apol_Types::typelist $Apol_Types::attriblist]
			set bothlist [lsort -dictionary $bothlist]
			$cBox configure -values $bothlist
		}
   	        roles {
		        $cBox configure -values $Apol_Roles::role_list
		}
		default {
			$cBox configure -values ""
		}
	}	
	return 0
}

proc Apol_RBAC::create {nb} {
    variable opts
    variable resultsbox
    variable list_src
    variable list_tgt
    variable list_dflt_role
    variable global_asSource
    variable global_any
    variable use_src_list
    variable list_types 
    variable list_attribs 
    variable list_roles
    variable use_dflt_role
    variable use_tgt_list
    global tcl_platform

    # Layout frames
    set frame [$nb insert end $ApolTop::rbac_tab -text "RBAC Rules"]
    set pw1 [PanedWindow $frame.pw1 -side left -weights available]
    $pw1 add -minsize 110
    $pw1 add -weight 4
    set topf  [frame [$pw1 getframe 0].topf]
    set bottomf [frame [$pw1 getframe 1].bottomf]

    # Placing layout frames
    pack $pw1 -fill both -expand yes
    pack $topf -fill both -expand yes     
    pack $bottomf -fill both -expand yes

    # Major subframes
    set pw2 [PanedWindow $topf.pw2 -side top -weights available]
    $pw2 add -minsize 110
    $pw2 add -weight 6
    set obox [TitleFrame [$pw2 getframe 1].obox -text "Search Criteria"]
    set tbox [TitleFrame [$pw2 getframe 0].tbox -text "Rule Selection"]
    set dbox [TitleFrame $bottomf.dbox -text "RBAC Rules Display"]
    #set okbox [frame $topf.okbox]
    
    # Placing major subframes
    pack $pw2 -fill both -expand yes
    pack $obox -side right -anchor w -fill both -padx 5 -expand yes
    pack $tbox -side left -anchor w -fill both -padx 5 -expand yes
    #pack $okbox -side left -anchor w -fill both 
    pack $dbox -side left -fill both -expand yes -anchor e -pady 5 -padx 5
    
    # Rule selection subframe
    set fm [$tbox getframe]
    set optsfm [frame $fm.optsfm]

    # Search options subframe 
    set frame [$obox getframe]

    # Search options section subframes used to group the action button widgets
    set fm_buttons [frame $frame.ta4 -relief flat -borderwidth 1]

    # Search options subframe - src role section
    set fm_src [frame $frame.src_role \
    	-relief flat -borderwidth 1]
    
    # Search options subframe - target role/type/attrib section
    set fm_tgt [frame $frame.tgt \
    	-relief flat -borderwidth 1]

    # Search options subframe - default role section
    set fm_dflt_role [frame $frame.dflt_role \
    	-relief flat -borderwidth 1]
    
    pack $fm_buttons -side right -anchor e -padx 5 -fill both
    pack $fm_src -side left -anchor nw -padx 5 -fill x -padx 5
    pack $fm_tgt -side left -fill x -anchor nw -padx 5
    pack $fm_dflt_role -side left -anchor n -fill x -padx 5
    
    # Widgets for rule selection subframe
    checkbutton $optsfm.allow -text "Allow" -variable Apol_RBAC::opts(allow) \
	-command "Apol_RBAC::enable_disable_tgt_dflt_sections" -offvalue 0 -onvalue 1
    checkbutton $optsfm.trans -text "Transition" -variable Apol_RBAC::opts(transition) \
	-command "Apol_RBAC::enable_disable_tgt_dflt_sections" -offvalue 0 -onvalue 1
           
    # Widgets for src role section
    set list_src [ComboBox $fm_src.cb -helptext "First role search parameter"  \
    	-textvariable Apol_RBAC::src_role -helptext "Type or select a role" ]   
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list.
    bindtags $list_src.e [linsert [bindtags $list_src.e] 3 list_src_Tag]
    bind list_src_Tag <KeyPress> { ApolTop::_create_popup $Apol_RBAC::list_src %W %K }
    set global_asSource [radiobutton $fm_src.source_1 -text "As source" \
			 -variable Apol_RBAC::opts(which_1) \
			 -value source  \
			 -command "Apol_RBAC::enable_disable_tgt_dflt_sections"]
    set global_any [radiobutton $fm_src.any -text "Any " \
			-variable Apol_RBAC::opts(which_1) \
			-value any  \
		        -command "Apol_RBAC::enable_disable_tgt_dflt_sections"]
    set use_src_list [checkbutton $fm_src.use_src_list -text $Apol_RBAC::m_use_src_role \
	-variable Apol_RBAC::opts(use_src_list) \
        -command "Apol_RBAC::useSearch $list_src 1"]
   
    # Widgets for tgt role/type/attrib section 
    set list_tgt [ComboBox $fm_tgt.cb2 -helptext "Target search parameter"  \
    	-textvariable Apol_RBAC::tgt_selection -helptext "Type or select a type/attribute/role" ]
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list.
    bindtags $list_tgt.e [linsert [bindtags $list_tgt.e] 3 list_tgt_Tag]
    bind list_tgt_Tag <KeyPress> { ApolTop::_create_popup $Apol_RBAC::list_tgt %W %K }
    set use_tgt_list [checkbutton $fm_tgt.use_3 -text $Apol_RBAC::m_disable_tgt \
		-variable Apol_RBAC::opts(use_tgt_list) \
		-command "Apol_RBAC::useSearch $list_tgt 2" ]
    set list_types [radiobutton $fm_tgt.list_types -text "Types" \
    	-variable Apol_RBAC::opts(list_type) -value types \
	-command {Apol_RBAC::populate_listbox $Apol_RBAC::list_tgt} ]
    set list_attribs [radiobutton $fm_tgt.list_attribs -text "Attribs" \
    	-variable Apol_RBAC::opts(list_type) -value attribs \
        -command {Apol_RBAC::populate_listbox $Apol_RBAC::list_tgt } ]
    set list_roles [radiobutton $fm_tgt.list_roles -text "Roles" \
    	-variable Apol_RBAC::opts(list_type) -value roles \
        -command {Apol_RBAC::populate_listbox $Apol_RBAC::list_tgt} ]
   
    # Widget items for use default role section
    set list_dflt_role [ComboBox $fm_dflt_role.cb3 -helptext "First role search parameter"  \
		-textvariable Apol_RBAC::dflt_role -helptext "Type or select a role" ]   
    # ComboBox is not a simple widget, it is a mega-widget, and bindings for mega-widgets are non-trivial.
    # If bindtags is invoked with only one argument, then the current set of binding tags for window is 
    # returned as a list. 
    bindtags $list_dflt_role.e [linsert [bindtags $list_dflt_role.e] 3 list_dflt_role_Tag]
    bind list_dflt_role_Tag <KeyPress> { ApolTop::_create_popup $Apol_RBAC::list_dflt_role %W %K }
    set use_dflt_role [checkbutton $fm_dflt_role.use_3 -text $Apol_RBAC::m_disable_dflt_role \
		-variable Apol_RBAC::opts(use_dflt_list) \
	        -command "Apol_RBAC::useSearch $list_dflt_role 3" ]

    # Display results window
    set sw [ScrolledWindow [$dbox getframe].sw -auto none]
    set resultsbox [text [$sw getframe].text -bg white -wrap none -state disabled]
    $sw setwidget $resultsbox
    
    # Action buttons
    button $fm_buttons.ok -text OK -width 6 -command {Apol_RBAC::searchRoles}
    #button $fm_buttons.print -text Print -width 6 -command {ApolTop::unimplemented}

    # Placing rule selections
    pack $optsfm.allow $optsfm.trans -anchor nw -side top -pady 1
    pack $optsfm -side left -fill x -expand yes -anchor nw
    
    # Placing action buttons
    pack $fm_buttons.ok -side top -pady 5 -anchor se
   
    # Placing widgets in src role section
    pack $use_src_list -anchor w
    pack $list_src -anchor w -expand yes -fill x -padx 5
    pack $global_asSource $global_any -side left -ipady 5 -fill y -expand yes
    
    # Placing widgets in tgt section
    pack $use_tgt_list -anchor w -side top
    pack $list_tgt -anchor w -expand yes -fill x -padx 5 
    pack $list_types $list_attribs $list_roles -side left -pady 7 -fill y -expand yes
    # Placing widget items for default role section
    pack $use_dflt_role -anchor w
    pack $list_dflt_role -anchor w -expand yes -fill x -padx 5

    # Placing display window
    pack $sw -side left -expand yes -fill both     
       
    Apol_RBAC::init_options

    return $frame	
}


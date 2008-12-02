# Copyright (C) 2001-2003 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets



##############################################################
# ::Apol_Types
#  
# The Types page
##############################################################
namespace eval Apol_Types {
# opts(opt), where opt =
# types			use types
# typeattribs		if types, also include attribs
# typealiases 		if types, also include aliases
# attribs		use attribs
# attribtypes		if attribs, also include types
# attribtypeattribs	if attribs and attrib types, also type's other attribs
# usesrchstr		use value of srchstr in searches
	variable opts
	set opts(types)			1
	set opts(typeattribs)		1
	set opts(typealiases)		1
	set opts(attribs)		0
	set opts(attribtypes)		0
	set opts(attribtypeattribs)	0
	set opts(usesrchstr)		0
	variable srchstr ""
	variable typelist ""
	variable attriblist ""

	# Global Widgets
	variable alistbox
	variable tlistbox
	variable resultsbox
	variable types_select 
	variable typeattribs 
	variable typealiases 
	variable attribs_select 
	variable a_types 
	variable a_typeattribs
	variable sString 
	variable sEntry 
	
	# callback procedures for the listbox items menu. Each element in this list is an embedded list of 2 items.
	# The 2 items consist of the command label and the function name. The tabname will be added as an
	# argument to the callback procedure.
	variable types_menu_callbacks	""
    	variable attribs_menu_callbacks	""
}

proc Apol_Types::open { } {
	variable typelist
	variable attriblist
            
	set rt [catch {set typelist [apol_GetNames types]} err]
	if {$rt != 0} {
		return -code error $err
	}
	set typelist [lsort $typelist]
	set rt [catch {set attriblist [apol_GetNames attribs]} err]
	if {$rt != 0} {
		return -code error $err
	}
	set attriblist [lsort $attriblist]
	return 0
}

proc Apol_Types::close { } {
        Apol_Types::init_options
        set Apol_Types::srchstr ""
	set Apol_Types::typelist ""
	set Apol_Types::attriblist ""
	$Apol_Types::resultsbox configure -state normal
	$Apol_Types::resultsbox delete 0.0 end
	ApolTop::makeTextBoxReadOnly $Apol_Types::resultsbox
	
	return 0
}

proc Apol_Types::free_call_back_procs { } {
       	variable types_menu_callbacks	
    	variable attribs_menu_callbacks	
	
	set types_menu_callbacks ""
	set attribs_menu_callbacks ""
	return 0
}

proc Apol_Types::init_options { } {
    variable types_select 
    variable typeattribs 
    variable typealiases 
    variable attribs_select 
    variable a_types 
    variable a_typeattribs
    variable sString 
    variable sEntry 
    variable opts
    set opts(types)			1
    set opts(typeattribs)		1
    set opts(typealiases)		1
    set opts(attribs)		        0
    set opts(attribtypes)		0
    set opts(attribtypeattribs)	        0
    set opts(usesrchstr)		0

    Apol_Types::enable_disable_incl_attribs $a_typeattribs
    Apol_Types::enable_disable_ta $typeattribs $typealiases 1 
    Apol_Types::enable_disable_ta $a_typeattribs $a_types 2
    Apol_Types::_useSearch $sEntry 
    
    return 0
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Types::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_Types::set_Focus_to_Text {} {
	focus $Apol_Types::resultsbox
	return 0
}

proc Apol_Types::popupTypeInfo {which ta} {
	set rt [catch {set info [apol_GetSingleTypeInfo 0 0 $ta]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}

	set w .ta_infobox
	set rt [catch {destroy $w} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}
	toplevel $w 
	wm title $w "$ta"
	wm protocol $w WM_DELETE_WINDOW "destroy $w"
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
	return 0
}

proc Apol_Types::popup_files_from_fc_database {which ta} {
	ApolTop::setBusyCursor
	set rt [catch {set results [Apol_File_Contexts::get_fc_files_for_ta $which $ta]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err. \n\nIf you need to load an index file, go to the File Context tab."
		ApolTop::resetBusyCursor
		return -1
	}

	set w .ta_fcbox
	set rt [catch {destroy $w} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		ApolTop::resetBusyCursor
		return -1
	}
	toplevel $w 
	wm title $w "$ta"
	wm protocol $w WM_DELETE_WINDOW "destroy $w"
    	wm withdraw $w
    	
	set sf [ScrolledWindow $w.sf  -scrollbar both -auto both]
	set f [text [$sf getframe].f -font {helvetica 10} -wrap none -width 35 -height 10]
	$sf setwidget $f
     	set b1 [button $w.close -text Close -command "catch {destroy $w}" -width 10]
     	pack $b1 -side bottom -anchor s -padx 5 -pady 5 
	pack $sf -fill both -expand yes
	foreach path $results {
     		$f insert end "$path\n"
     	}
 	wm geometry $w +50+50
 	wm deiconify $w
 	$f configure -state disabled
 	ApolTop::resetBusyCursor
	return 0
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Types::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

proc Apol_Types::searchTypes {} {
	variable opts
	variable srchstr
	
	if {$opts(usesrchstr) && $srchstr == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided!"
		return
	}
	
	set rt [catch {set results [apol_GetTypeInfo $opts(types) $opts(typeattribs) \
		$opts(attribs) $opts(attribtypes) $opts(attribtypeattribs) \
		$opts(typealiases) $opts(usesrchstr) $srchstr]} err]	
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return 
	} else {
	    $Apol_Types::resultsbox configure -state normal
	    $Apol_Types::resultsbox delete 0.0 end
	    $Apol_Types::resultsbox insert end $results
	    ApolTop::makeTextBoxReadOnly $Apol_Types::resultsbox
        }
	return 0
}

proc Apol_Types::_useSearch { entry } {
    if { $Apol_Types::opts(usesrchstr) } {
    	$entry config -state normal   -background white
    } else {
    	$entry config -state disabled  -background  $ApolTop::default_bg_color
    }
    return 0
}

proc Apol_Types::enable_disable_ta { b1 b2 num } {
   
    if { $num == 1 } {
	
	if { $Apol_Types::opts(types) } {
	    $b1 configure -state normal
	    $b2 configure -state normal
	} else {
	    $b1 configure -state disabled
	    $b1 deselect
	    $b2 configure -state disabled
	    $b2 deselect
	}
    } elseif { $num == 2 } {
	if { $Apol_Types::opts(attribs) } {
	    $b1 configure -state normal
	} else {
	    $b1 configure -state disabled
	    $b1 deselect
	    $b2 configure -state disabled
	    $b2 deselect
	}
    }
    return 0
}

proc Apol_Types::enable_disable_incl_attribs { cb } {
     
     if { $Apol_Types::opts(attribtypes) } {
	$cb configure -state normal
     } else {
	$cb configure -state disabled
	$cb deselect
     }
 }

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Types::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

proc Apol_Types::create {nb} {
    variable tlistbox 
    variable alistbox 
    variable resultsbox 
    variable srchstr 
    variable types_select 
    variable typeattribs 
    variable typealiases 
    variable attribs_select 
    variable a_types 
    variable a_typeattribs
    variable sString 
    variable sEntry 
    variable opts
    variable types_menu_callbacks
    variable attribs_menu_callbacks
    
    # Layout frames
    set frame [$nb insert end $ApolTop::types_tab -text "Types"]
    set topf  [frame $frame.topf]

    # Paned Windows
    set pw1   [PanedWindow $topf.pw -side top]
    set pane  [$pw1 add ]
    set spane [$pw1 add -weight 5]
    set pw2   [PanedWindow $pane.pw -side left]
    set tpane [$pw2 add -weight 3]
    set apane [$pw2 add ]

    # Major subframes
    set tbox [TitleFrame $tpane.tbox -text "Types"]
    set abox [TitleFrame $apane.abox -text "Attributes"]
    set obox [TitleFrame $spane.obox -text "Search Options"]
    set rbox [TitleFrame $spane.rbox -text "Search Results"]

    # Placing layout frames and major subframes
    pack $obox -pady 2 -padx 2 -fill x  -anchor n 
    pack $tbox -padx 2 -side left -fill both -expand yes
    pack $abox -padx 2 -side left -fill both -expand yes
    pack $rbox -pady 2 -padx 2 -fill both -expand yes
    pack $pw1 -fill both -expand yes
    pack $pw2 -fill both -expand yes	
    pack $topf -fill both -expand yes 
    
    # Types listbox
    set sw_t       [ScrolledWindow [$tbox getframe].sw -auto both]
    set tlistbox [listbox [$sw_t getframe].lb -height 18 -width 20 -highlightthickness 0 \
		      -listvar Apol_Types::typelist -bg white] 
    $sw_t setwidget $tlistbox 
    
    # Attributes listbox 
    set sw_a       [ScrolledWindow [$abox getframe].sw -auto both]
    set alistbox [listbox [$sw_a getframe].lb -height 7 -width 20 -highlightthickness 0 \
		      -listvar Apol_Types::attriblist -bg white]        
    $sw_a setwidget $alistbox 
    
    # Popup menu widget
    menu .popupMenu_types
    set types_menu_callbacks [lappend types_menu_callbacks {"Display Type Info" "Apol_Types::popupTypeInfo type"}]
    set types_menu_callbacks [lappend types_menu_callbacks {"Display Files Labeled With This Type" "Apol_Types::popup_files_from_fc_database type"}]
    menu .popupMenu_attribs
    set attribs_menu_callbacks [lappend attribs_menu_callbacks {"Display Attribute Info" "Apol_Types::popupTypeInfo attrib"}]
    set attribs_menu_callbacks [lappend attribs_menu_callbacks {"Display Files Labeled With Types For This Attribute" "Apol_Types::popup_files_from_fc_database attrib"}]
    
    # Binding events to the both listboxes
    bindtags $tlistbox [linsert [bindtags $tlistbox] 3 tlist_Tag]  
    bindtags $alistbox [linsert [bindtags $alistbox] 3 alist_Tag]  
    bind tlist_Tag <Double-ButtonPress-1>  { Apol_Types::popupTypeInfo "type" [$Apol_Types::tlistbox get active]}
    bind alist_Tag <Double-ButtonPress-1> { Apol_Types::popupTypeInfo "attrib" [$Apol_Types::alistbox get active]}
    bind tlist_Tag <Button-3> { ApolTop::popup_listbox_Menu \
    	%W %x %y .popupMenu_types $Apol_Types::types_menu_callbacks \
    	$Apol_Types::tlistbox}      
    bind alist_Tag <Button-3> { ApolTop::popup_listbox_Menu \
    	%W %x %y .popupMenu_attribs $Apol_Types::attribs_menu_callbacks \
    	$Apol_Types::alistbox} 
    
    bind tlist_Tag <<ListboxSelect>> { focus -force $Apol_Types::tlistbox}
    bind alist_Tag <<ListboxSelect>> { focus -force $Apol_Types::alistbox}
     
    # Search options section      
    set ofm [$obox getframe]
    set fm_attribs_select [frame $ofm.ao -relief sunken -borderwidth 1]
    set fm_sString [frame $ofm.so -relief sunken -borderwidth 1]
    set okbox [frame $ofm.okbox]
    set fm_types_select [frame $ofm.to -relief sunken -borderwidth 1]
        
    # Placing search options section frames
    pack $okbox -side right -anchor n -fill both -expand yes -padx 5
    pack $fm_types_select -side left -anchor n  -padx 5 -fill y
    pack $fm_attribs_select -side left -anchor n -fill y 
    pack $fm_sString -side left -anchor n -fill both -expand yes -padx 5
    
    # Placing types and attributes listboxes frame
    pack $sw_t -fill both -expand yes
    pack $sw_a -fill both -expand yes

    set typeattribs [checkbutton $fm_types_select.typeattribs -text "Include Attribs" \
	-variable Apol_Types::opts(typeattribs) -padx 10] 
    set typealiases [checkbutton $fm_types_select.typealiases -text "Use Aliases" \
	-variable Apol_Types::opts(typealiases) -padx 10]
    set types_select [checkbutton $fm_types_select.type -text "Show Types" -variable Apol_Types::opts(types) \
	-command "Apol_Types::enable_disable_ta $typeattribs $typealiases 1"]

    # Attributes search section
    set a_typeattribs [checkbutton $fm_attribs_select.typeattribs -text "Include Type Attribs" \
	-variable Apol_Types::opts(attribtypeattribs) -padx 10 \
	-offvalue 0 \
        -onvalue 1]
    set a_types [checkbutton $fm_attribs_select.types -text "Include Types" \
	-variable Apol_Types::opts(attribtypes) \
	-padx 10 \
	-offvalue 0 \
	-command "Apol_Types::enable_disable_incl_attribs $a_typeattribs" \
	-onvalue 1]
    set attribs_select [checkbutton $fm_attribs_select.type -text "Show Attributes" \
	-variable Apol_Types::opts(attribs) \
	-command "Apol_Types::enable_disable_ta $a_types $a_typeattribs 2"]
  
    # Search string section widgets
    set sEntry [Entry $fm_sString.entry -textvariable Apol_Types::srchstr -width 40 \
		    -helptext "Enter a regular expression string for which to search"]
    set sString [checkbutton $fm_sString.cb -variable Apol_Types::opts(usesrchstr) -text "Search Using Regular Expression" \
		     -command "Apol_Types::_useSearch $sEntry"] 

    # Action buttons
    button $okbox.ok -text OK -width 6 -command { Apol_Types::searchTypes }
    #button $okbox.print -text Print -width 6 -command {ApolTop::unimplemented}
        
    # Display results window
    set sw [ScrolledWindow [$rbox getframe].sw -auto none]
    set resultsbox [text [$sw getframe].text -bg white -wrap none -state disabled]
    $sw setwidget $resultsbox

    # Placing search options section widgets
    pack $types_select $typeattribs $typealiases -anchor w  
    pack $attribs_select $a_types $a_typeattribs -anchor w  
    pack $sString -side top -anchor nw
    pack $sEntry -expand yes -padx 5 -pady 5 -fill x 
    pack $okbox.ok -side top -padx 5 -pady 5 -anchor se 
  
    # Placing display widgets
    pack $sw -side left -expand yes -fill both 
    
    Apol_Types::init_options

    return $frame	
}


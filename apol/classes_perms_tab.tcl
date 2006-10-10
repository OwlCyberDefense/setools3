# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.3+, with BWidgets

##############################################################
# ::Apol_Class_Perms
#  
# The Classes/Permissions page
##############################################################
namespace eval Apol_Class_Perms {
# opts(opt), where opt =
# show_classes1		Show class objects (first section)
# show_perms1 		if show_classes1, also show permissions
# show_comm_perms1	if show_classes1 and show_perms1, also expand common permissions
# show_comm_perms2	Show common permissions (second section)
# show_classes2		if show_comm_perms2, also show permissions
# show_perms2		if show_comm_perms2, also show object classes
# show_perms3		Show permissions (third section)
# show_classes3		if show_perms3, also show object classes
# show_comm_perms3	if show_perms3, also expand common permissions
# usesrchstr		use value of srchstr in searches
	variable opts
	set opts(show_classes1)		1
	set opts(show_comm_perms1)	0
	set opts(show_perms1)		0
	set opts(show_classes2)		0
	set opts(show_comm_perms2)	0
	set opts(show_perms2)		0
	set opts(show_classes3)		0
	set opts(show_comm_perms3)	0
	set opts(show_perms3)		0
	set opts(usesrchstr)		0
	variable class_list 		""
	variable common_perms_list 	""
	variable perms_list		""
	variable srchstr		""
	
	# Global Widgets
    	variable show_classes1
  	variable show_classes2
 	variable show_classes3
        variable show_comm_perms1
        variable show_comm_perms2
        variable show_comm_perms3
        variable show_perms1
        variable show_perms2
        variable show_perms3
    	variable resultsbox 
    	variable sString 
    	variable sEntry
}

proc Apol_Class_Perms::open { } {
	variable class_list
	variable common_perms_list
	variable perms_list
	
	# Check whether "classes" are included in the current opened policy file
	if {$ApolTop::contents(classes) == 1} {
		set rt [catch {set class_list [apol_GetNames classes]} err]
		if {$rt != 0} {
			return -code error $err
		}
		set class_list [lsort $class_list]
	} 	
	# Check whether "perms" are included in the current opened policy file		
	if {$ApolTop::contents(perms) == 1} {
		set rt [catch {set common_perms_list [apol_GetNames common_perms]} err]
		if {$rt != 0} {
			return -code error $err
		}
		set common_perms_list [lsort $common_perms_list]
		set rt [catch {set perms_list [apol_GetNames perms]} err]
		if {$rt != 0} {
			return -code error $err
		}
		set perms_list [lsort $perms_list]
	} 	
	
	return 0
}

proc Apol_Class_Perms::close { } {
	variable class_list 		""
	variable common_perms_list 	""
	variable perms_list		""
	variable srchstr		""
	
	Apol_Class_Perms::init_options	
        set class_list 		""
	set common_perms_list 	""
	set perms_list 		""
	set srchstr 		""
	$Apol_Class_Perms::resultsbox configure -state normal
	$Apol_Class_Perms::resultsbox delete 0.0 end
	ApolTop::makeTextBoxReadOnly $Apol_Class_Perms::resultsbox 
	      
	return 0
}

proc Apol_Class_Perms::free_call_back_procs { } {
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Class_Perms::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_Class_Perms::set_Focus_to_Text {} {
	focus $Apol_Class_Perms::resultsbox
	return 0
}

proc Apol_Class_Perms::enable_disable_widgets { } {
	variable opts
     	variable show_classes1
  	variable show_classes2
 	variable show_classes3
        variable show_comm_perms1
        variable show_comm_perms2
        variable show_comm_perms3
        variable show_perms1
        variable show_perms2
        variable show_perms3
        variable sString 
    	variable sEntry
        
        $sString configure -state normal        
    	if { $opts(show_classes1) } {
		$show_perms1 configure -state normal
		if { $opts(show_perms1) } {
			$show_comm_perms1 configure -state normal
		} else {
			$show_comm_perms1 configure -state disabled
			$show_comm_perms1 deselect
		}		
     	} else {
     		$show_perms1 configure -state disabled
		$show_comm_perms1 configure -state disabled
		$show_perms1 deselect
		$show_comm_perms1 deselect
    	}
    	if { $opts(show_comm_perms2) } {
		$show_perms2 configure -state normal
		$show_classes2 configure -state normal
     	} else {
     		$show_perms2 configure -state disabled
		$show_classes2 configure -state disabled
		$show_perms2 deselect
		$show_classes2 deselect
    	}
    	if { $opts(show_perms3) } {
		$show_classes3 configure -state normal
		$show_comm_perms3 configure -state normal
     	} else {
     		$show_classes3 configure -state disabled
		$show_comm_perms3 configure -state disabled
		$show_classes3 deselect
		$show_comm_perms3 deselect
    	}
    	# Disable the regex check button if all search criteria is not selected
    	if { !$opts(show_classes1) && !$opts(show_comm_perms2) && !$opts(show_perms3) } {
    		$sString deselect 
    		$sString configure -state disabled
    	}
    	Apol_Class_Perms::useSearch $sEntry
    	update
    	return 0
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Class_Perms::goto_line { line_num } {
	variable resultsbox
	
	ApolTop::goto_line $line_num $resultsbox
	return 0
}

proc Apol_Class_Perms::init_options { } {
	variable show_classes1
  	variable show_classes2
 	variable show_classes3
        variable show_comm_perms1
        variable show_comm_perms2
        variable show_comm_perms3
        variable show_perms1
        variable show_perms2
        variable show_perms3
    	variable sString 
    	variable sEntry 
    	variable opts
    	set opts(show_classes1)		1
	set opts(show_comm_perms1)	0
	set opts(show_perms1)		0
	set opts(show_classes2)		0
	set opts(show_comm_perms2)	0
	set opts(show_perms2)		0
	set opts(show_classes3)		0
	set opts(show_comm_perms3)	0
	set opts(show_perms3)		0
	set opts(usesrchstr)		0

	Apol_Class_Perms::enable_disable_widgets
	
    	return 0
}

proc Apol_Class_Perms::popupInfo {which name} {
	set rt [catch {set info [apol_GetSingleClassPermInfo $name $which]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}

	set w .class_perms_infobox
	set rt [catch {destroy $w} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}
	toplevel $w 
	wm title $w "$name"
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
proc Apol_Class_Perms::search { str case_Insensitive regExpr srch_Direction } {
	variable resultsbox
	
	ApolTop::textSearch $resultsbox $str $case_Insensitive $regExpr $srch_Direction
	return 0
}

proc Apol_Class_Perms::search_Class_Perms {} {
	variable opts
	variable srchstr
	
	if {$opts(usesrchstr) && $srchstr == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided!"
		return
	}
	if { !$opts(show_classes1) && !$opts(show_comm_perms2) && !$opts(show_perms3) } {
    		tk_messageBox -icon error -type ok -title "Error" -message "No search criteria provided!"
		return
    	}
    	
	set rt [catch {set results [apol_GetClassPermInfo $opts(show_classes1) $opts(show_perms1) \
		 $opts(show_comm_perms1) $opts(show_comm_perms2) $opts(show_perms2) $opts(show_classes2) \
		 $opts(show_perms3) $opts(show_classes3) $opts(show_comm_perms3) $opts(usesrchstr) \
		 $srchstr]} err]
		 
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return 
	} else {
	    $Apol_Class_Perms::resultsbox configure -state normal
	    $Apol_Class_Perms::resultsbox delete 0.0 end
	    $Apol_Class_Perms::resultsbox insert end $results
	    ApolTop::makeTextBoxReadOnly $Apol_Class_Perms::resultsbox 
        }
	return 0	
}

proc Apol_Class_Perms::useSearch { entry } {
        if { $Apol_Class_Perms::opts(usesrchstr) } {
        	$entry config -state normal -background  white
        } else {
        	$entry config -state disabled -background  $ApolTop::default_bg_color
        }
        return 0
}

proc Apol_Class_Perms::create {nb} {
        variable show_classes1
        variable show_classes2
        variable show_classes3
        variable show_comm_perms1
        variable show_comm_perms2
        variable show_comm_perms3
        variable show_perms1
        variable show_perms2
        variable show_perms3
        variable sString 
        variable sEntry 
        variable resultsbox 
        variable opts
        
        # Layout frames
        set frame [$nb insert end $ApolTop::class_perms_tab -text "Classes/Perms"]
        set topf  [frame $frame.topf]
    
        # Paned Windows
        set pw1   [PanedWindow $topf.pw -side top]
        set pane  [$pw1 add ]
        set search_pane [$pw1 add -weight 5]
        set pw2   [PanedWindow $pane.pw -side left]
        set class_pane 	[$pw2 add -weight 2]
        set common_pane 	[$pw2 add ]
        set perms_pane 	[$pw2 add -weight 3]
        global tcl_platform
    
        # Major subframes
        set classes_box 	[TitleFrame $class_pane.tbox -text "Object Classes"]
        set common_box 		[TitleFrame $common_pane.abox -text "Common Permissions"]
        set perms_box 		[TitleFrame $perms_pane.abox -text "Permissions"]
        set options_box 	[TitleFrame $search_pane.obox -text "Search Options"]
        set results_box 	[TitleFrame $search_pane.rbox -text "Search Results"]
    
        # Placing layout frames and major subframes
        pack $options_box -pady 2 -padx 2 -fill x  -anchor n 
        pack $classes_box -padx 2 -side left -fill both -expand yes
        pack $common_box -padx 2 -side left -fill both -expand yes
        pack $perms_box -padx 2 -side left -fill both -expand yes
        pack $results_box -pady 2 -padx 2 -fill both -expand yes
        pack $pw1 -fill both -expand yes
        pack $pw2 -fill both -expand yes	
        pack $topf -fill both -expand yes 
        
        # Object Classes listbox
	set class_listbox [Apol_Widget::makeScrolledListbox [$classes_box getframe].lb -height 10 -width 20 -listvar Apol_Class_Perms::class_list]
	Apol_Widget::setListboxCallbacks $class_listbox \
		{{"Display Object Class Info" {Apol_Class_Perms::popupInfo class}}}

        # Common Permissions listbox
	set common_listbox [Apol_Widget::makeScrolledListbox [$common_box getframe].lb -height 5 -width 20 -listvar Apol_Class_Perms::common_perms_list]
	Apol_Widget::setListboxCallbacks $common_listbox \
		{{"Display Common Permission Class Info" {Apol_Class_Perms::popupInfo common_perm}}}
        
        # Permissions listbox 
	set perms_listbox [Apol_Widget::makeScrolledListbox [$perms_box getframe].lb -height 10 -width 20 -listvar Apol_Class_Perms::perms_list]
	Apol_Widget::setListboxCallbacks $perms_listbox \
		{{"Display Permission Info" {Apol_Class_Perms::popupInfo perm}}}

        # Placing object classes, common permissions and permissions listboxe frames
        pack $class_listbox -fill both -expand yes
        pack $common_listbox -fill both -expand yes
        pack $perms_listbox -fill both -expand yes
        
        # Search options section      
        set opts_fm 			[$options_box getframe]
        set fm_classes_select 		[frame $opts_fm.class -relief sunken -borderwidth 1]
        set fm_comm_perms_select 	[frame $opts_fm.common -relief sunken -borderwidth 1]
        set fm_perms_select 		[frame $opts_fm.perms -relief sunken -borderwidth 1]
        set fm_sString 			[frame $opts_fm.so -relief flat -borderwidth 1]
        set okbox 			[frame $opts_fm.okbox]
        
        # Placing search options section frames
        pack $okbox -side right -anchor n -fill both -expand yes -padx 5
        pack $fm_classes_select -side left -anchor n -padx 5 -pady 2 -fill y 
        pack $fm_comm_perms_select -side left -anchor n -fill y -pady 2
        pack $fm_perms_select -side left -anchor n -fill y -padx 5 -pady 2
        pack $fm_sString -side left -anchor n -fill both -expand yes -padx 5   
        
        # First set of checkbuttons
        set show_classes1 [checkbutton $fm_classes_select.show_classes1 -text "Object Classes" \
    	-variable Apol_Class_Perms::opts(show_classes1) \
    	-command { Apol_Class_Perms::enable_disable_widgets }] 
        set show_perms1 [checkbutton $fm_classes_select.show_perms1 -text "Include Perms" \
    	-variable Apol_Class_Perms::opts(show_perms1) -padx 10 \
    	-command { Apol_Class_Perms::enable_disable_widgets }]
        set show_comm_perms1 [checkbutton $fm_classes_select.show_comm_perms1 -text "Expand Common Perms" \
    	-variable Apol_Class_Perms::opts(show_comm_perms1) -padx 10]
    	
        # Second set of checkbuttons
        set show_comm_perms2 [checkbutton $fm_comm_perms_select.show_comm_perms2 -text "Common Permissions" \
    	-variable Apol_Class_Perms::opts(show_comm_perms2) \
    	-command { Apol_Class_Perms::enable_disable_widgets }] 
        set show_perms2 [checkbutton $fm_comm_perms_select.show_perms2 -text "Include Perms" \
    	-variable Apol_Class_Perms::opts(show_perms2) -padx 10]
        set show_classes2 [checkbutton $fm_comm_perms_select.show_classes2 -text "Object Classes" \
    	-variable Apol_Class_Perms::opts(show_classes2) -padx 10]
        
        # Third set of checkbuttons	
        set show_perms3 [checkbutton $fm_perms_select.show_perms3 -text "Permissions" \
    	-variable Apol_Class_Perms::opts(show_perms3) \
    	-command { Apol_Class_Perms::enable_disable_widgets }] 
        set show_classes3 [checkbutton $fm_perms_select.show_classes3 -text "Object Classes" \
    	-variable Apol_Class_Perms::opts(show_classes3) -padx 10]
        set show_comm_perms3 [checkbutton $fm_perms_select.show_comm_perms3 -text "Common Perms" \
    	-variable Apol_Class_Perms::opts(show_comm_perms3) -padx 10]
          
        # Search string section widgets
        set sEntry [Entry $fm_sString.entry -textvariable Apol_Class_Perms::srchstr -width 40 \
    		    -helptext "Enter a regular expression"]
        set sString [checkbutton $fm_sString.cb -variable Apol_Class_Perms::opts(usesrchstr) \
        		-text "Search using regular expression" \
    		   	-command "Apol_Class_Perms::useSearch $sEntry"] 
    
        # Action buttons
        button $okbox.ok -text OK -width 6 -command { Apol_Class_Perms::search_Class_Perms }
        #button $okbox.print -text Print -width 6 -command {ApolTop::unimplemented}
            
        # Display results window
        set sw [ScrolledWindow [$results_box getframe].sw -auto none]
        set resultsbox [text [$sw getframe].text -bg white -wrap none -state disabled] 
        $sw setwidget $resultsbox
        
        # Placing search options section widgets
        pack $show_classes1 $show_perms1 $show_comm_perms1 -anchor w 
        pack $show_comm_perms2 $show_perms2 $show_classes2 -anchor w  
        pack $show_perms3 $show_classes3 $show_comm_perms3 -anchor w
        pack $sString -side top -anchor w -expand yes 
        pack $sEntry -fill x -anchor center -expand yes 
        pack $okbox.ok -side top -padx 5 -pady 5 -anchor se 
      
        # Placing display widgets
        pack $sw -side left -expand yes -fill both 
        
        # Initializes widget options
        Apol_Class_Perms::init_options
    
        return $frame	
}

                                                                                                                                                                                              
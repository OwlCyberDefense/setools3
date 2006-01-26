# Copyright (C) 2001-2006 Tresys Technology, LLC
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
	set opts(show_files)		0
	set opts(incl_context)		0
	set opts(incl_class)		0
	variable srchstr ""
	variable typelist ""
	variable attriblist ""
	variable progressmsg		""
	variable progress_indicator	-1
	
	# Global Widgets
	variable resultsbox
	variable types_select 
	variable typeattribs 
	variable typealiases 
	variable attribs_select 
	variable a_types 
	variable a_typeattribs
	variable sString 
	variable sEntry 
	variable fc_incl_context
    	variable fc_incl_class
    	variable fc_files_select
    	variable progressDlg 		.progress_Dlg
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
    set opts(show_files)		0
    set opts(incl_context)		0
    set opts(incl_class)		0
	
    Apol_Types::enable_disable_incl_attribs $a_typeattribs
    Apol_Types::enable_disable_checkbuttons $typeattribs $typealiases 1 
    Apol_Types::enable_disable_checkbuttons $a_typeattribs $a_types 2
    if {$ApolTop::libsefs == 1} {
    	#Apol_Types::enable_disable_checkbuttons $Apol_Types::fc_incl_class $Apol_Types::fc_incl_context 3
    }
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

proc Apol_Types::on_show_more_info_button_clicked {which lb} {
	set sel [$lb curselection]
	if {$sel != ""} {
		Apol_Types::popupTypeInfo $which [$lb get $sel]
	}
}

proc Apol_Types::popupTypeInfo {which ta} {
	if {$ta == ""} {
		return
	}
	ApolTop::setBusyCursor
	set info_fc ""
	set index_file_loaded 0
	set rt [catch {set info_ta [apol_GetSingleTypeInfo 0 0 $ta]} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		ApolTop::resetBusyCursor
		return -1
	}
	if {$ApolTop::libsefs == 1} {
		if {[Apol_File_Contexts::is_db_loaded]} {
			set rt [catch {set info_fc [Apol_File_Contexts::get_fc_files_for_ta $which $ta]} err]
			if {$rt != 0} {
				tk_messageBox -icon error -type ok -title "Error" \
					-message "$err. \n\nIf you need to load an index file, go to the File Context tab."
				ApolTop::resetBusyCursor
				return -1
			}
			set index_file_loaded 1
		} 
	}
	ApolTop::resetBusyCursor
	set w .ta_infobox
	set rt [catch {destroy $w} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "$err"
		return -1
	}

	toplevel $w 
	wm title $w "$ta"
	wm protocol $w WM_DELETE_WINDOW " "
    	wm withdraw $w
    	
    	set top_f [frame $w.top_f]
    	set bot_f [frame $w.bot_f]
    	set notebook [NoteBook $top_f.nb]
    	
    	set ta_info_tab [$notebook insert end ta_info_tab]
    	if {$ApolTop::libsefs == 1} {
		set fc_info_tab [$notebook insert end fc_info_tab -text "Files"]
	}
	
	if {$which == "type"} {
		$notebook itemconfigure ta_info_tab -text "Attributes"
	} else {
		$notebook itemconfigure ta_info_tab -text "Types"
	}
	set s_ta [ScrolledWindow [$notebook getframe ta_info_tab].s_ta  -scrollbar both -auto both]
	set f_ta [text [$s_ta getframe].f -font {helvetica 10} -wrap none -width 35 -height 10 -bg white]
	$s_ta setwidget $f_ta
	
	if {$ApolTop::libsefs == 1} {
		if {$which != "type"} {
			set lbl [Label [$notebook getframe fc_info_tab].lbl \
				-text "Files labeled with types that are members of this attribute:" \
				-justify left]
		}
		set s_fc [ScrolledWindow [$notebook getframe fc_info_tab].s_fc  -scrollbar both -auto both]
		set f_fc [text [$s_fc getframe].f -font {helvetica 10} -wrap none -width 35 -height 10 -bg white]
		$s_fc setwidget $f_fc
	}
	
     	set b_close [Button $bot_f.b_close -text "Close" -command "catch {destroy $w}" -width 10]
     	
     	pack $top_f -side top -anchor nw -fill both -expand yes
     	pack $bot_f -side bottom -anchor sw -fill x
     	pack $b_close -side bottom -anchor center -fill x -expand yes -padx 2 -pady 2
	pack $s_ta -fill both -expand yes
	$notebook compute_size
	pack $notebook -fill both -expand yes -padx 4 -pady 4
	$notebook raise [$notebook page 0]
	$f_ta insert 0.0 $info_ta
	$f_ta configure -state disabled 
	
	if {$ApolTop::libsefs == 1} {
		if {$which != "type"} {
			pack $lbl -side top -side top -anchor nw
		}
		pack $s_fc -fill both -expand yes -side top
	     	if {$index_file_loaded} {
		     	if {$info_fc != ""} {
		     		set num 0
		     		foreach item $info_fc {
				     	foreach {ctxt class path} $item {}
				     	$f_fc insert end "$ctxt\t     $class\t     $path\n"
				     	incr num
				}
		     		$f_fc insert 1.0 "Number of files: $num\n\n"
			} else {
				$f_fc insert end "No files found."
			}
		} else {
			$f_fc insert 0.0 "No index file is loaded. If you would like to load an index file, go to the File Context tab."
		}
		$f_fc configure -state disabled
	}
 		
 	wm geometry $w 400x400
 	wm deiconify $w
 	wm protocol $w WM_DELETE_WINDOW "destroy $w"
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
	variable progressDlg
	
	if {[winfo exists $progressDlg]} {
		# another search already going, so ignore this search request
		return
	}
	if {$opts(usesrchstr) && $srchstr == ""} {
		tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided!"
		return
	}
	if {$opts(types) == 0 && $opts(attribs) == 0} {
		tk_messageBox -icon error -type ok -title "Error" -message "No search options provided!"
		return
	}
    
	set Apol_Types::progressmsg "Searching...This may take a while."
	ProgressDlg $progressDlg \
		-parent $ApolTop::mainframe \
        	-textvariable Apol_Types::progressmsg \
        	-variable Apol_Types::progress_indicator \
        	-maximum 3 \
        	-width 45
	ApolTop::setBusyCursor
	set rt [catch {set results [apol_GetTypeInfo $opts(types) $opts(typeattribs) \
		$opts(attribs) $opts(attribtypes) $opts(attribtypeattribs) \
		$opts(typealiases) $opts(usesrchstr) $srchstr \
		$opts(show_files) $opts(incl_context) $opts(incl_class)]} err]
	destroy $progressDlg
	ApolTop::resetBusyCursor
	if {$rt != 0} {	
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err \n\nNote:If you need to load an index file, go to the File Context tab."
	} else {
	    $Apol_Types::resultsbox configure -state normal
	    $Apol_Types::resultsbox delete 0.0 end
	    $Apol_Types::resultsbox insert end $results
	    ApolTop::makeTextBoxReadOnly $Apol_Types::resultsbox
        }
}

proc Apol_Types::_useSearch { entry } {
    if { $Apol_Types::opts(usesrchstr) } {
    	$entry config -state normal   -background white
    } else {
    	$entry config -state disabled  -background  $ApolTop::default_bg_color
    }
    return 0
}

proc Apol_Types::enable_disable_checkbuttons { b1 b2 opt } {
	switch -- $opt {
		1 {
			set status $Apol_Types::opts(types)
		}
		2 {
			set status $Apol_Types::opts(attribs)
		}
		3 {
			set status $Apol_Types::opts(show_files)
		}
		default { 
			puts "Invalid option for num argument: $num\n"
		}
	}
	if {$status} {
	    $b1 configure -state normal
	    $b2 configure -state normal
	} else {
	    $b1 deselect
	    $b2 deselect
	    $b1 configure -state disabled
	    $b2 configure -state disabled
	}
    variable sEntry
    variable sString
    # disable regular expression searching if both types and attribs
    # are disabled
    if {$Apol_Types::opts(types) == 0 && $Apol_Types::opts(attribs) == 0} {
        set Apol_Types::opts(usesrchstr) 0
        $sString deselect
        $sString configure -state disabled
        _useSearch $sEntry
    } else {
        variable sString
        $sString configure -state normal
        _useSearch $sEntry
    }
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
    variable fc_incl_context
    variable fc_incl_class
    variable fc_files_select
    
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
    set tlistbox [Apol_Widget::makeScrolledListbox [$tbox getframe].types -height 18 -width 20 -listvar Apol_Types::typelist]
    Apol_Widget::setListboxCallbacks $tlistbox \
        {{"Show Type Info" {Apol_Types::popupTypeInfo type}}}
    set t_button [Button [$tbox getframe].t_button -text "Show Type Info" \
                      -command [list Apol_Types::on_show_more_info_button_clicked type [Apol_Widget::getScrolledListbox $tlistbox]] \
    	-width 10]

    # Attributes listbox
    set alistbox [Apol_Widget::makeScrolledListbox [$abox getframe].attribs -height 7 -width 20 -highlightthickness 0 -listvar Apol_Types::attriblist]
    Apol_Widget::setListboxCallbacks $alistbox {{"Show Attribute Info" {Apol_Types::popupTypeInfo attrib}}}
    set a_button [Button [$abox getframe].a_button -text "Show Attribute Info" \
                      -command [list Apol_Types::on_show_more_info_button_clicked attrib [Apol_Widget::getScrolledListbox $alistbox]] \
    	-width 10]

    # Search options section      
    set ofm [$obox getframe]
    set fm_attribs_select [frame $ofm.ao -relief sunken -borderwidth 1]
    set fm_sString [frame $ofm.so -relief sunken -borderwidth 1]
    if {$ApolTop::libsefs == 1} {
    	#set fm_fc_files [frame $ofm.fm_fc_files -relief sunken -borderwidth 1]
    }
    set okbox [frame $ofm.okbox]
    set fm_types_select [frame $ofm.to -relief sunken -borderwidth 1]
        
    # Placing search options section frames
    pack $t_button $a_button -side bottom -fill x -anchor sw -padx 2 -pady 2
    pack $okbox -side right -anchor n -fill both -expand yes -padx 5
    pack $fm_types_select -side left -anchor n  -padx 5 -fill y
    pack $fm_attribs_select -side left -anchor nw -fill y -padx 5
    if {$ApolTop::libsefs == 1} {
    	 #pack $fm_fc_files -side left -anchor nw -fill y -padx 5
    }
    pack $fm_sString -side left -anchor n -fill both -expand yes -padx 5
    
    # Placing types and attributes listboxes frame
    pack $tlistbox -fill both -expand yes
    pack $alistbox -fill both -expand yes

    set typeattribs [checkbutton $fm_types_select.typeattribs -text "Include Attribs" \
	-variable Apol_Types::opts(typeattribs) -padx 10] 
    set typealiases [checkbutton $fm_types_select.typealiases -text "Use Aliases" \
	-variable Apol_Types::opts(typealiases) -padx 10]
    set types_select [checkbutton $fm_types_select.type -text "Show Types" -variable Apol_Types::opts(types) \
	 -command [list Apol_Types::enable_disable_checkbuttons $typeattribs $typealiases 1]]

    # Attributes search section
    set a_typeattribs [checkbutton $fm_attribs_select.typeattribs -text "Include Type Attribs" \
	-variable Apol_Types::opts(attribtypeattribs) -padx 10 \
	-offvalue 0 \
        -onvalue 1]
    set a_types [checkbutton $fm_attribs_select.types -text "Include Types" \
	-variable Apol_Types::opts(attribtypes) \
	-padx 10 \
	-offvalue 0 \
	-command [list Apol_Types::enable_disable_incl_attribs $a_typeattribs] \
	-onvalue 1]
    set attribs_select [checkbutton $fm_attribs_select.type -text "Show Attributes" \
	-variable Apol_Types::opts(attribs) \
	-command "Apol_Types::enable_disable_checkbuttons $a_types $a_typeattribs 2"]
    
    if {$ApolTop::libsefs == 1} {
#	    set fc_incl_context [checkbutton $fm_fc_files.fc_incl_context -text "Include Context" \
#		-variable Apol_Types::opts(incl_context)]
#	    set fc_incl_class [checkbutton $fm_fc_files.fc_incl_class -text "Include Object Class" \
#		-variable Apol_Types::opts(incl_class)]	
#	    set fc_files_select [checkbutton $fm_fc_files.fc_files_select -text "Show Files" \
#		-variable Apol_Types::opts(show_files) \
#		-command "Apol_Types::enable_disable_checkbuttons $fc_incl_context $fc_incl_class 3"]
    }
    
    # Search string section widgets
    set sEntry [Entry $fm_sString.entry -textvariable Apol_Types::srchstr -width 40 \
		    -helptext "Enter a regular expression string for which to search"]
    set sString [checkbutton $fm_sString.cb -variable Apol_Types::opts(usesrchstr) -text "Search Using Regular Expression" \
		     -command [list Apol_Types::_useSearch $sEntry]]

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
    if {$ApolTop::libsefs == 1} {
	    #pack $fc_files_select -side top -anchor nw -expand yes -padx 2
	    #pack $fc_incl_context $fc_incl_class -side top -padx 6 -pady 2 -anchor nw -expand yes
    }
    pack $sString -side top -anchor nw
    pack $sEntry -expand yes -padx 5 -pady 5 -fill x 
    pack $okbox.ok -side top -padx 5 -pady 5 -anchor se 
  
    # Placing display widgets
    pack $sw -side left -expand yes -fill both 
    
    Apol_Types::init_options

    return $frame	
}


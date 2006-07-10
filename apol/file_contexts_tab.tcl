# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget
#
# Author: <don.patterson@tresys.com>
#

##############################################################
# ::Apol_File_Contexts
#  
# The File Contexts page
##############################################################
namespace eval Apol_File_Contexts {
    variable opts
    variable widgets
	
	# Global Widgets
	variable entry_dir
	variable entry_fn
	variable create_fc_dlg		.fc_db_create_Dlg
	
    variable info_button_text \
"This tab allows you to create and load a file context index.  The file
context index is an on-disk database which contains the labeling
information for an entire filesystem. Once an index has been created
you can query the database by enabling and selecting a user, type,
object class or path. A query can also use regular expressions, if
this is enabled.\n
The results of the context query show the number of results followed
by a list of the matching files. The first field is the full context
followed by the object class of the file and lastly the path."
}

proc Apol_File_Contexts::display_analysis_info {} {
    Apol_Widget::showPopupParagraph "File Contexts Information" $Apol_File_Contexts::info_button_text
} 

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_File_Contexts::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results) $str $case_Insensitive $regExpr $srch_Direction
}

# ----------------------------------------------------------------------------------------
#  Command Apol_File_Contexts::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_File_Contexts::set_Focus_to_Text {} {
    focus $Apol_File_Contexts::widgets(results)
}

proc Apol_File_Contexts::is_db_loaded {} {
    return $Apol_File_Contexts::opts(db_loaded)
}

proc Apol_File_Contexts::populate_combo_boxes {} {
    variable widgets
	
    if {[catch {apol_FC_Index_DB_Get_Items types} types]} {
        tk_messageBox -icon error -type ok -title "Error" \
            -message "Error getting types from file context database: $types.\n"
        return
    }
    $widgets(type) configure -values [lsort $types]
	
    if {[catch {apol_FC_Index_DB_Get_Items users} users]} {
        tk_messageBox -icon error -type ok -title "Error" \
            -message "Error getting users from file context database: $users.\n"
        return
    }
    $widgets(user) configure -values [lsort $users]

    if {[catch {apol_FC_Index_DB_Get_Items classes} classes]} {
        tk_messageBox -icon error -type ok -title "Error" \
            -message "Error getting object classes from file context database: $classes.\n"
        return
    }
    # remove the special class "all_files"
    set i [lsearch -exact $classes "all_files"]
    $widgets(objclass) configure -values [lsort [lreplace $classes $i $i]]
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::open
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::open { } {
    return 0
} 

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::initialize
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::initialize { } {
    variable opts
    variable widgets

    array set opts {
        useUser 0       user {}    useUserRegex 0
        useObjclass 0   objclass {}
        useType 0       type {}    useTypeRegx 0
        useRange 0      range {}   useRangeRegex 0   fc_is_mls 1
        usePath 0       path {}    usePathRegex 0

        showContext 1  showObjclass 1
        indexFilename {}
        db_loaded 0
    }

    $widgets(user) configure -values {}
    $widgets(type) configure -values {}
    $widgets(objclass) configure -values {}
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::close
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::close { } {
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_File_Contexts::close_fc_db
    Apol_File_Contexts::initialize
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::get_fc_files_for_ta
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::get_fc_files_for_ta {which ta} {	
	set types_list ""
	set results ""
	
	if {$which == "type"} {
		set types_list [lappend types_list $ta]
	} else {
		# Get all types for the attribute
		set rt [catch {set attrib_typesList [apol_GetAttribTypesList $ta]} err]	
		if {$rt != 0} {
			return -code error $err
		}
		foreach type $attrib_typesList {
			if {$type != "self"} {
				set types_list [lappend types_list $type]
			}	
		}
		set types_list $attrib_typesList
	}
    set results [apol_Search_FC_Index_DB {} $types_list {} {} {} 0 0 0 0]
    set return_list {}
    foreach fscon $results {
        lappend return_list $fscon
    }
    return $return_list
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::search_fc_database
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::search_fc_database { } {
    variable opts
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {$opts(useUser)} {
        if {[set user [list $opts(user)]] == {{}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No user selected."
            return
        }
    } else {
        set user {}
    }
    if {$opts(useObjclass)} {
        if {[set objclass [list $opts(objclass)]] == {{}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No object class selected."
            return
        }
    } else {
        set objclass {}
    }
    if {$opts(useType)} {
        if {[set type [list $opts(type)]] == {{}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No type selected."
            return
        }
    } else {
        set type {}
    }
    if {$opts(fc_is_mls) && $opts(useRange)} {
        if {[set range [list $opts(range)]] == {{}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No MLS range selected."
            return
        }
    } else {
        set range {}
    }
    if {$opts(usePath)} {
        if {[set path [list $opts(path)]] == {{}}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No path selected."
            return
        }
    } else {
        set path {}
    }

    ApolTop::setBusyCursor
    set rt [catch {apol_Search_FC_Index_DB \
                       $user $type $objclass $range $path \
                       $opts(useUserRegex) $opts(useTypeRegex) \
                       $opts(useRangeRegex) $opts(usePathRegex)} results]
    ApolTop::resetBusyCursor
    if {$rt != 0} {
        tk_messageBox -icon error -type ok -title "Error" -message $results
        return
    }

    if {$results == {}} {
        Apol_Widget::appendSearchResultText $widgets(results) "Search returned no results."
    } else {
        set text "FILES FOUND ([llength $results]):\n\n"
        foreach fscon $results {
            foreach {ctxt class path} $fscon {break}
            if {$opts(showContext)} {
                append text [format "%-46s" $ctxt]
            }
            if {$opts(showObjclass)} {
                append text [format "  %-14s" $class]
            }
            append text "  $path\n"
	}
        Apol_Widget::appendSearchResultText $widgets(results) $text
    }
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::display_create_db_dlg
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::display_create_db_dlg {} {
	variable entry_dir
	variable entry_fn
	variable create_fc_dlg
	variable b1_create_dlg
	variable b2_create_dlg
	
	set w $create_fc_dlg
	destroy $w
	toplevel $w 
	wm title $w "Create Index File"
	wm protocol $w WM_DELETE_WINDOW " "
    	wm withdraw $w
    	
    	set t_frame [frame $w.t_frame]
    	set f1 [frame $t_frame.f1]
    	set f2 [frame $t_frame.f2]
    	set f3 [frame $t_frame.f3]
    	set lbl_fn 	[Label $f1.lbl_fn -justify left -text "Save file:"]
    	set lbl_dir 	[Label $f1.lbl_dir -justify left -text "Directory to index:"]
	set entry_dir 	[entry $f2.entry_path -width 30 -bg white]
	set browse_dir 	[button $f3.button1 -text "Browse" -width 8 -command {
		set txt [$Apol_File_Contexts::entry_dir get]
		if {[string is space $txt]} {
			set txt "/"
		} elseif {![file isdirectory $txt]} {
			set txt [file dirname $txt]
		} 
		set dir_n [tk_chooseDirectory \
			-title "Select Directory to Index..." \
			-parent $Apol_File_Contexts::create_fc_dlg \
			-initialdir $txt]
		if {$dir_n != ""} {
			$Apol_File_Contexts::entry_dir delete 0 end
			$Apol_File_Contexts::entry_dir insert end $dir_n
		}	
	}]
	set entry_fn 	[entry $f2.entry_fn -width 30 -bg white]
	set browse_fn 	[button $f3.button2 -text "Browse" -width 8 -command {
		set txt [$Apol_File_Contexts::entry_fn get]
		if {[string is space $txt]} {
			set dir_name "/"
			set init_file "/"
		} elseif {![file isdirectory $txt]} {
			set dir_name [file dirname $txt]
			set init_file $txt
		} else {
			set dir_name $txt
			set init_file ""
		}
		set file_n [tk_getSaveFile \
			-title "Select File to Save..." \
			-parent $Apol_File_Contexts::create_fc_dlg \
			-initialdir $dir_name \
			-initialfile $init_file]
		if {$file_n != ""} {
			$Apol_File_Contexts::entry_fn delete 0 end
			$Apol_File_Contexts::entry_fn insert end $file_n
		}	
	}]
	$entry_dir insert end "/"
	
	set b_frame [frame $w.b_frame]
     	set b1_create_dlg [button $b_frame.create -text Create \
     		-command {Apol_File_Contexts::create_fc_db $Apol_File_Contexts::create_fc_dlg} \
     		-width 10]
     	set b2_create_dlg [button $b_frame.close1 -text Cancel \
     		-command {catch {
     			destroy $Apol_File_Contexts::create_fc_dlg; grab release $Apol_File_Contexts::create_fc_dlg}} \
     		-width 10]
     	
     	pack $b_frame -side bottom -expand yes -anchor center
     	pack $t_frame -side top -fill both -expand yes
     	pack $f1 $f2 $f3 -side left -anchor nw -padx 5 -pady 5
     	pack $b1_create_dlg $b2_create_dlg -side left -anchor nw -padx 5 -pady 5 
	pack $lbl_fn $lbl_dir -anchor nw -side top -pady 6
	pack $entry_fn $entry_dir -anchor nw -side top -expand yes -pady 5
	pack $browse_fn $browse_dir -anchor nw -side top -expand yes -pady 3
     
 	wm geometry $w +50+50
 	wm deiconify $w
 	grab $w
 	wm protocol $w WM_DELETE_WINDOW "destroy $w"
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::create_and_load_fc_db
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::create_and_load_fc_db {fname dir_str} {
    variable opts
	set rt [catch {apol_Create_FC_Index_File $fname $dir_str} err]
	if {$rt != 0} {
		return -code error "Error while creating the index file: $err"
	} 
	set rt [catch {apol_Load_FC_Index_File $fname} err]
	if {$rt != 0} {
		return -code error \
			"The index file was created successfully, however, there was an error while loading: $err"
	}
    Apol_File_Contexts::initialize
    set opts(fc_is_mls) [apol_FC_Is_MLS]
    set opts(indexFilename) $fname
    set opts(db_loaded) 1
    Apol_File_Contexts::populate_combo_boxes
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::create_fc_db
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::create_fc_db {dlg} {
	variable entry_dir
	variable entry_fn
	variable b1_create_dlg
	variable b2_create_dlg
    variable opts
	
	# Disable the buttons to prevent multiple clicking from causing tk errors.
	$b1_create_dlg configure -state disabled
	$b2_create_dlg configure -state disabled
	set fname [$entry_fn get]
	set dir_str [$entry_dir get]

    set opts(progressMsg) "Creating index file.. .This may take a while."
    set opts(progressVal) -1
    set progress_dlg [ProgressDlg .apol_fc_progress -parent . \
                          -textvariable Apol_File_Contexts::opts(progressMsg) \
                          -variable Apol_File_Contexts::opts(progressVal) \
                          -maximum 3 -width 45]
    ApolTop::setBusyCursor
    update idletasks
	set rt [catch {Apol_File_Contexts::create_and_load_fc_db $fname $dir_str} err]
    ApolTop::resetBusyCursor
    destroy $progress_dlg
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "$err\nSee stderr for more information."
		$b1_create_dlg configure -state normal
		$b2_create_dlg configure -state normal
            raise $dlg
		return
	} 
	destroy $dlg
	grab release $dlg
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::load_fc_db
#  	returns 1 if loaded successfully, otherwise, unsucessful or user canceled
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::load_fc_db { } {
    variable opts
	
    	set db_file [tk_getOpenFile -title "Select Index File to Load..." -parent $ApolTop::mainframe]
	if {$db_file != ""} {	
		set rt [catch {apol_Load_FC_Index_File $db_file} err]
		if {$rt != 0} {
			tk_messageBox -icon error -type ok -title "Error" -message \
				"Error loading file context database: $err\nSee stderr for more information."
			return -1
		} 
		Apol_File_Contexts::initialize
            set opts(fc_is_mls) [apol_FC_Is_MLS]
            set opts(indexFilename) $db_file
		set opts(db_loaded) 1
		Apol_File_Contexts::populate_combo_boxes
		return 1
	}
	return 0
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::close_fc_db
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::close_fc_db { } {
    variable opts
	set rt [catch {apol_Close_FC_Index_DB} err]
	if {$rt != 0} {
		tk_messageBox -icon error -type ok -title "Error" \
			-message "Error closing file context database: $err.\n"
		return
	}
    set opts(db_loaded) 0
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_File_Contexts::goto_line { line_num } {
    variable widgets
    ApolTop::goto_line $line_num $widgets(results)
}

# ------------------------------------------------------------------------------
#  Command Apol_File_Contexts::create
# ------------------------------------------------------------------------------
proc Apol_File_Contexts::create {nb} {
    variable opts
    variable widgets
		
    # Layout frames
    set frame [$nb insert end $ApolTop::file_contexts_tab -text "File Contexts"]
    set options_pane [frame $frame.top]
    set results_pane [frame $frame.bottom]
    pack $options_pane -expand 0 -fill x
    pack $results_pane -expand 1 -fill both -pady 2

    # File Context Index frame
    set status [TitleFrame $options_pane.status -text "File Context Index"]
    set status_frame [$status getframe]
    set status_buttons [ButtonBox $status_frame.bb -homogeneous 0 -padx 2]
    $status_buttons add -text "Create and Load" -width 15 \
        -command {Apol_File_Contexts::display_create_db_dlg}
    $status_buttons add -text "Load" -width 8 \
        -command {Apol_File_Contexts::load_fc_db}
    set status_text [frame $status_frame.t]
    label $status_text.l -text "Loaded Index:"
    set status1 [label $status_text.t -textvariable Apol_File_Contexts::opts(statusText)]
    set status2 [label $status_text.t2 -textvariable Apol_File_Contexts::opts(statusText2) -fg red]
    trace add variable Apol_File_Contexts::opts(indexFilename) write \
        [list Apol_File_Contexts::changeStatusLabel $status1 $status2]
    grid $status_text.l $status1 -sticky w
    grid x $status2 -sticky w -pady 2
    pack $status_buttons $status_text -side left -anchor nw -padx 2 -pady 4
    pack $status -side top -expand 0 -fill x -pady 2 -padx 2

    # Search options subframes
    set optionsbox [TitleFrame $options_pane.opts -text "Search Options"]
    pack $optionsbox -fill both -expand yes -padx 2 -pady 2
    set options_frame [$optionsbox getframe]

    set show_frame [frame $options_frame.show]
    set user_frame [frame $options_frame.user]
    set objclass_frame [frame $options_frame.objclass]
    set type_frame [frame $options_frame.type]
    set range_frame [frame $options_frame.range]
    set path_frame [frame $options_frame.path]
    grid $show_frame $user_frame $objclass_frame $type_frame $range_frame $path_frame \
        -padx 2 -sticky news
    foreach idx {1 2 3 4} {
        grid columnconfigure $options_frame $idx -uniform 1 -weight 0
    }
    grid columnconfigure $options_frame 0 -weight 0 -pad 8
    grid columnconfigure $options_frame 5 -weight 0

    set show_context [checkbutton $show_frame.context \
                          -variable Apol_File_Contexts::opts(showContext) \
                          -text "Show context"]
    set show_objclass [checkbutton $show_frame.objclass \
                           -variable Apol_File_Contexts::opts(showObjclass) \
                           -text "Show object class"]
    pack $show_context $show_objclass -side top -anchor nw

    # User subframe
    checkbutton $user_frame.enable -text "User" \
        -variable Apol_File_Contexts::opts(useUser)
    set widgets(user) [ComboBox $user_frame.box -width 8 -autopost 1 \
                           -textvariable Apol_File_Contexts::opts(user) \
                           -helptext "Type or select a user"]
    set user_regex [checkbutton $user_frame.regex \
                        -variable Apol_File_Contexts::opts(useUserRegex) \
                        -text "Regular expression"]
    trace add variable Apol_File_Contexts::opts(useUser) write \
        [list Apol_File_Contexts::toggleEnable $widgets(user) -entrybg $user_regex]
    pack $user_frame.enable -side top -anchor nw
    pack $widgets(user) -side top -anchor nw -padx 4 -expand 0 -fill x
    pack $user_regex -side top -anchor nw -padx 4

    # Object class subframe
    checkbutton $objclass_frame.enable -text "Object class" \
        -variable Apol_File_Contexts::opts(useObjclass)
    set widgets(objclass) [ComboBox $objclass_frame.box -width 8 -autopost 1 \
                               -textvariable Apol_File_Contexts::opts(objclass) \
                               -helptext "Type or select an object class"]
    trace add variable Apol_File_Contexts::opts(useObjclass) write \
        [list Apol_File_Contexts::toggleEnable $widgets(objclass) -entrybg {}]
    pack $objclass_frame.enable -side top -anchor nw
    pack $widgets(objclass) -side top -anchor nw -padx 4 -expand 0 -fill x

    # Type subframe
    checkbutton $type_frame.enable -text "Type" \
        -variable Apol_File_Contexts::opts(useType)
    set widgets(type) [ComboBox $type_frame.box -width 8 -autopost 1 \
                           -textvariable Apol_File_Contexts::opts(type) \
                           -helptext "Type or select a type"]
    set type_regex [checkbutton $type_frame.regex \
                        -variable Apol_File_Contexts::opts(useTypeRegex) \
                        -text "Regular expression"]
    trace add variable Apol_File_Contexts::opts(useType) write \
        [list Apol_File_Contexts::toggleEnable $widgets(type) -entrybg $type_regex]
    pack $type_frame.enable -side top -anchor nw
    pack $widgets(type) -side top -anchor nw -padx 4 -expand 0 -fill x
    pack $type_regex -side top -anchor nw -padx 4

    # MLS Range subframe
    set range_cb [checkbutton $range_frame.enable \
                      -variable Apol_File_Contexts::opts(useRange) -text "MLS range"]
    set range_entry [entry $range_frame.range -width 12 \
                         -textvariable Apol_File_Contexts::opts(range)]
    set range_regex [checkbutton $range_frame.regex \
                         -variable Apol_File_Contexts::opts(useRangeRegex) \
                         -text "Regular expression"]
    trace add variable Apol_File_Contexts::opts(useRange) write \
        [list Apol_File_Contexts::toggleEnable $range_entry -bg $range_regex]
    trace add variable Apol_File_Contexts::opts(fc_is_mls) write \
        [list Apol_File_Contexts::toggleRange $range_cb $range_entry $range_regex]
    pack $range_cb -side top -anchor nw
    pack $range_entry -side top -anchor nw -padx 4 -expand 0 -fill x
    pack $range_regex -side top -anchor nw -padx 4

    # Path subframe
    checkbutton $path_frame.enable \
        -variable Apol_File_Contexts::opts(usePath) -text "File path"
    set path_entry [entry $path_frame.path -width 24 -textvariable Apol_File_Contexts::opts(path)]
    set path_regex [checkbutton $path_frame.regex \
                        -variable Apol_File_Contexts::opts(usePathRegex) \
                        -text "Regular expression"]
    trace add variable Apol_File_Contexts::opts(usePath) write \
        [list Apol_File_Contexts::toggleEnable $path_entry -bg $path_regex]
    pack $path_frame.enable -side top -anchor nw
    pack $path_entry -side top -anchor nw -padx 4 -expand 0 -fill x
    pack $path_regex -side top -anchor nw -padx 4

    # Action Buttons
    set action_buttons [ButtonBox $options_frame.bb -orient vertical -homogeneous 1 -pady 2]
    $action_buttons add -text OK -width 6 -command {Apol_File_Contexts::search_fc_database}
    $action_buttons add -text "Info" -width 6 -command {Apol_File_Contexts::display_analysis_info}
    grid $action_buttons -row 0 -column 6 -padx 5 -pady 5 -sticky ne
    grid columnconfigure $options_frame 6 -weight 1

    set results_frame [TitleFrame $results_pane.results -text "Matching Files"]
    set widgets(results) [Apol_Widget::makeSearchResults [$results_frame getframe].results]
    pack $widgets(results) -expand yes -fill both
    pack $results_frame -expand yes -fill both -padx 2

    initialize
    return $frame
}

proc Apol_File_Contexts::changeStatusLabel {label1 label2 name1 name2 opt} {
    variable opts
    if {$opts(indexFilename) == ""} {
        set opts(statusText) "No Index File Loaded"
        $label1 configure -fg red
        set opts(statusText2) {}
    } else {
        set opts(statusText) $opts(indexFilename)
        $label1 configure -fg black
        if {$opts(fc_is_mls)} {
            set opts(statusText2) "Database contexts include MLS ranges."
            $label2 configure -fg black
        } else {
            set opts(statusText2) "Database contexts do not include MLS ranges."
            $label2 configure -fg red
        }
    }
}

proc Apol_File_Contexts::toggleEnable {entry bgcmd regex name1 name2 op} {
    variable opts
    if {$opts($name2)} {
        $entry configure -state normal $bgcmd white
        catch {$regex configure -state normal}
    } else {
        $entry configure -state disabled $bgcmd $ApolTop::default_bg_color
        catch {$regex configure -state disabled}
    }
}

proc Apol_File_Contexts::toggleRange {cb entry regex name1 name2 op} {
    variable opts
    if {$opts(fc_is_mls)} {
        $cb configure -state normal
        if {$opts(useRange)} {
            $entry configure -state normal -bg white
            $regex configure -state normal
        }
    } else {
        $cb configure -state disabled
        $entry configure -state disabled -bg $ApolTop::default_bg_color
        $regex configure -state disabled
    }
}

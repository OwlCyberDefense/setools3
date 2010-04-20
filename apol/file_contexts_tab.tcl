# Copyright (C) 2001-2007 Tresys Technology, LLC
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

namespace eval Apol_File_Contexts {
    variable opts
    variable widgets

    variable info_button_text \
        "This tab allows the user to create and open a file context index.
The file context index is an on-disk database which contains the
labeling information for an entire filesystem.  Once an index has been
created it can then be queried by user, type, MLS range (if it
contains MLS information), object class, and/or path.\n

The result of the context query is a list of matching files, ordered
by path.  The first field is the full SELinux context, assuming that
'Show SELinux file context' is enabled.  If 'Show object class' is
enabled, then the next field is the type of file that matched; this
will be one of 'file', 'dir', and so forth.  The remaining field is
the full path to the file."
}

proc Apol_File_Contexts::create {tab_name nb} {
    variable opts
    variable widgets

    _initializeVars

    set frame [$nb insert end $tab_name -text "File Contexts"]
    set status [TitleFrame $frame.status -text "File Context Index"]
    set options [TitleFrame $frame.opts -text "Search Options"]
    set results [TitleFrame $frame.results -text "Matching Files"]
    pack $status $options -expand 0 -fill x -pady 2
    pack $results -expand 1 -fill both -pady 2

    # File Context Index frame
    set status_frame [$status getframe]
    set status_buttons [ButtonBox $status_frame.bb -homogeneous 1 -padx 2]
    $status_buttons add -text "Create and Open" -command {Apol_File_Contexts::_create_dialog}
    $status_buttons add -text "Open" -command {Apol_File_Contexts::_open_database}
    pack $status_buttons -side left -anchor nw -padx 2 -pady 4

    set status_text [frame $status_frame.t]
    pack $status_text -side left -anchor nw -padx 6 -pady 4
    label $status_text.l -text "Opened Index:"
    set status1 [label $status_text.t -textvariable Apol_File_Contexts::opts(statusText)]
    set status2 [label $status_text.t2 -textvariable Apol_File_Contexts::opts(statusText2) -fg red]
    trace add variable Apol_File_Contexts::opts(indexFilename) write \
        [list Apol_File_Contexts::_changeStatusLabel $status1 $status2]
    grid $status_text.l $status1 -sticky w
    grid x $status2 -sticky w -pady 2
    pack $status -side top -expand 0 -fill x -pady 2 -padx 2
    # invoke trace to set initial label text
    set opts(indexFilename) $opts(indexFilename)

    # Search options subframes
    set options_frame [$options getframe]
    set show_frame [frame $options_frame.show]
    set user_frame [frame $options_frame.user]
    set role_frame [frame $options_frame.role]
    set type_frame [frame $options_frame.type]
    set range_frame [frame $options_frame.range]
    set objclass_frame [frame $options_frame.objclass]
    set path_frame [frame $options_frame.path]
    grid $show_frame $user_frame $role_frame $type_frame $range_frame $objclass_frame $path_frame \
        -padx 2 -sticky news
    foreach idx {1 2 3 4 5} {
        grid columnconfigure $options_frame $idx -uniform 1 -weight 0
    }
    grid columnconfigure $options_frame 0 -weight 0 -pad 8
    grid columnconfigure $options_frame 6 -weight 0

    set use_regexp [checkbutton $show_frame.regexp \
                           -variable Apol_File_Contexts::opts(useRegexp) \
                           -text "Search using regular expression"]
    set show_context [checkbutton $show_frame.context \
                          -variable Apol_File_Contexts::opts(showContext) \
                          -text "Show SELinux file context"]
    set show_objclass [checkbutton $show_frame.objclass \
                           -variable Apol_File_Contexts::opts(showObjclass) \
                           -text "Show object class"]
    pack $use_regexp $show_context $show_objclass -side top -anchor nw

    checkbutton $user_frame.enable -text "User" \
        -variable Apol_File_Contexts::opts(useUser)
    set widgets(user) [entry $user_frame.e -width 12 \
                           -textvariable Apol_File_Contexts::opts(user)]
    trace add variable Apol_File_Contexts::opts(useUser) write \
        [list Apol_File_Contexts::_toggleEnable $widgets(user)]
    pack $user_frame.enable -side top -anchor nw
    pack $widgets(user) -side top -anchor nw -padx 4 -expand 0 -fill x

    checkbutton $role_frame.enable -text "Role" \
        -variable Apol_File_Contexts::opts(useRole)
    set widgets(role) [entry $role_frame.e -width 12 \
                           -textvariable Apol_File_Contexts::opts(role)]
    trace add variable Apol_File_Contexts::opts(useRole) write \
        [list Apol_File_Contexts::_toggleEnable $widgets(role)]
    pack $role_frame.enable -side top -anchor nw
    pack $widgets(role) -side top -anchor nw -padx 4 -expand 0 -fill x

    checkbutton $type_frame.enable -text "Type" \
        -variable Apol_File_Contexts::opts(useType)
    set widgets(type) [entry $type_frame.e -width 12 \
                           -textvariable Apol_File_Contexts::opts(type)]
    trace add variable Apol_File_Contexts::opts(useType) write \
        [list Apol_File_Contexts::_toggleEnable $widgets(type)]
    pack $type_frame.enable -side top -anchor nw
    pack $widgets(type) -side top -anchor nw -padx 4 -expand 0 -fill x

    checkbutton $objclass_frame.enable -text "Object class" \
        -variable Apol_File_Contexts::opts(useObjclass)
    set widgets(objclass) [entry $objclass_frame.e -width 12 \
                           -textvariable Apol_File_Contexts::opts(objclass)]
    trace add variable Apol_File_Contexts::opts(useObjclass) write \
        [list Apol_File_Contexts::_toggleEnable $widgets(objclass)]
    pack $objclass_frame.enable -side top -anchor nw
    pack $widgets(objclass) -side top -anchor nw -padx 4 -expand 0 -fill x

    set range_cb [checkbutton $range_frame.enable \
                      -variable Apol_File_Contexts::opts(useRange) -text "MLS range"]
    set range_entry [entry $range_frame.e -width 12 \
                         -textvariable Apol_File_Contexts::opts(range)]
    trace add variable Apol_File_Contexts::opts(useRange) write \
        [list Apol_File_Contexts::_toggleEnable $range_entry]
    trace add variable Apol_File_Contexts::opts(fc_is_mls) write \
        [list Apol_File_Contexts::_toggleRange $range_cb $range_entry]
    pack $range_cb -side top -anchor nw
    pack $range_entry -side top -anchor nw -padx 4 -expand 0 -fill x

    checkbutton $path_frame.enable \
        -variable Apol_File_Contexts::opts(usePath) -text "File path"
    set path_entry [entry $path_frame.path -width 24 \
                        -textvariable Apol_File_Contexts::opts(path)]
    trace add variable Apol_File_Contexts::opts(usePath) write \
        [list Apol_File_Contexts::_toggleEnable $path_entry]
    pack $path_frame.enable -side top -anchor nw
    pack $path_entry -side top -anchor nw -padx 4 -expand 0 -fill x

    set bb [ButtonBox $options_frame.bb -orient vertical -homogeneous 1 -pady 2]
    $bb add -text OK -width 6 -command {Apol_File_Contexts::_search}
    $bb add -text Info -width 6 -command {Apol_File_Contexts::_show_info}
    grid $bb -row 0 -column 7 -padx 5 -pady 5 -sticky ne
    grid columnconfigure $options_frame 7 -weight 1

    set widgets(results) [Apol_Widget::makeSearchResults [$results getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_File_Contexts::open {ppath} {
    if {[is_db_loaded]} {
        variable opts
        $opts(db) associatePolicy $::ApolTop::policy
    }
}

proc Apol_File_Contexts::close {} {
    _close_database
}

proc Apol_File_Contexts::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

proc Apol_File_Contexts::is_db_loaded {} {
    variable opts
    if {$opts(db) != {}} {
        return 1
    }
    return 0
}

proc Apol_File_Contexts::get_fc_files_for_ta {which ta} {
    set q [new_sefs_query]
    if {$which == "type"} {
        $q type $ta 0
    } else {
        $q type $ta 1
    }
    variable opts
    if {[catch {Apol_Progress_Dialog::wait "File Contexts" "Searching database for $ta" \
                    {
                        $opts(db) runQuery $q
                    }} results]} {
        tk_messageBox -icon error -type ok -title "File Contexts" -message $results
        delete_sefs_query $q
        return {}
    }
    delete_sefs_query $q
    return $results
}

#### private functions below ####

proc Apol_File_Contexts::_initializeVars {} {
    variable opts
    variable widgets

    array set opts {
        useUser 0       user {}
        useRole 0       role {}
        useType 0       type {}
        useObjclass 0   objclass {}
        useRange 0      range {}
        usePath 0       path {}

        useRegexp 0  showContext 1  showObjclass 1
        db {}
        fc_is_mls 1
        indexFilename {}
    }
}

proc Apol_File_Contexts::_show_info {} {
    .mainframe.frame.nb.fApol_File_Contexts.opts.f.bb.b1 configure -state disabled
    Apol_Widget::showPopupParagraph "File Contexts Information" $Apol_File_Contexts::info_button_text
    .mainframe.frame.nb.fApol_File_Contexts.opts.f.bb.b1 configure -state normal
}

proc Apol_File_Contexts::_changeStatusLabel {label1 label2 name1 name2 opt} {
    variable opts
    if {$opts(db) == {}} {
        set opts(statusText) "No Index File Opened"
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

proc Apol_File_Contexts::_toggleEnable {entry name1 name2 op} {
    variable opts
    if {$opts($name2)} {
        $entry configure -state normal -bg white
    } else {
        $entry configure -state disabled -bg $ApolTop::default_bg_color
    }
}

proc Apol_File_Contexts::_toggleRange {cb entry name1 name2 op} {
    variable opts
    if {$opts(fc_is_mls)} {
        $cb configure -state normal
        if {$opts(useRange)} {
            $entry configure -state normal -bg white
        }
    } else {
        $cb configure -state disabled
        $entry configure -state disabled -bg $ApolTop::default_bg_color
    }
}

proc Apol_File_Contexts::_create_dialog {} {
    variable opts

    set opts(new_filename) $opts(indexFilename)
    set opts(new_rootdir) "/"

    set d [Dialog .filecontexts_create -title "Create Index File" \
               -default 0 -cancel 1 -modal local -parent . -separator 1]
    $d add -text "OK" -command [list Apol_File_Contexts::_create_database $d] \
        -state disabled
    $d add -text "Cancel"

    set f [$d getframe]
    set file_l [label $f.file_l -justify left -anchor w -text "Save index to:"]
    set file_entry [entry $f.file_e -width 30 -bg white -takefocus 1\
                        -textvariable Apol_File_Contexts::opts(new_filename) \
                        -validate key \
                        -vcmd [list Apol_File_Contexts::_validateEntryKey %P $d new_rootdir]]
    focus $file_entry
    set file_browse [button $f.file_b -text "Browse" -width 8 -takefocus 1 \
                         -command [list Apol_File_Contexts::_browse_save]]

    set root_l [label $f.root_l -justify left -anchor w -text "Directory to index:"]
    set root_entry [entry $f.root_e -width 30 -bg white -takefocus 1 \
                        -textvariable Apol_File_Contexts::opts(new_rootdir) \
                        -validate key \
                        -vcmd [list Apol_File_Contexts::_validateEntryKey %P $d new_filename]]
    set root_browse [button $f.root_b -text "Browse" -width 8 -takefocus 1 \
                         -command [list Apol_File_Contexts::_browse_root]]

    grid $file_l $file_entry $file_browse -padx 4 -pady 2 -sticky ew
    grid $root_l $root_entry $root_browse -padx 4 -pady 2 -sticky ew
    grid columnconfigure $f 0 -weight 0
    grid columnconfigure $f 1 -weight 1
    grid columnconfigure $f 2 -weight 0

    $d draw
    destroy $d
}

proc Apol_File_Contexts::_browse_save {} {
    variable opts
    set f [tk_getSaveFile -initialfile $opts(new_filename) \
           -parent .filecontexts_create -title "Save Index"]
    if {$f != {}} {
        set opts(new_filename) $f
    }
}

proc Apol_File_Contexts::_browse_root {} {
    variable opts
    set f [tk_chooseDirectory -initialdir $opts(new_rootdir) \
               -parent .filecontexts_create -title "Directory to Index"]
    if {$f != {}} {
        set opts(new_rootdir) $f
    }
}

proc Apol_File_Contexts::_validateEntryKey {newvalue dialog othervar} {
    variable opts
    if {$newvalue == {} || $opts($othervar) == {}} {
        $dialog itemconfigure 0 -state disabled
    } else {
        $dialog itemconfigure 0 -state normal
    }
    return 1
}

proc Apol_File_Contexts::_create_database {dialog} {
    variable opts

    if {[catch {Apol_Progress_Dialog::wait "Create Database" "Scanning $opts(new_rootdir)" \
                    {
                        set db [apol_tcl_open_database_from_dir $opts(new_rootdir)]
                        $db save $opts(new_filename)
                        set db
                    } \
                } db] || $db == "NULL"} {
        tk_messageBox -icon error -type ok -title "Create Database" \
            -message [apol_tcl_get_info_string]
        return
    }
    if {$opts(db) != {}} {
        delete_sefs_fclist $opts(db)
    }
    _initializeVars
    set opts(db) $db
    set opts(fc_is_mls) [$db isMLS]
    set opts(indexFilename) $opts(new_filename)
    if {[ApolTop::is_policy_open]} {
        $opts(db) associatePolicy $::ApolTop::policy
    }
    $dialog enddialog {}
}

proc Apol_File_Contexts::_open_database {} {
    variable opts

    set f [tk_getOpenFile -initialfile $opts(indexFilename) -parent . \
               -title "Open Database"]
    if {$f == {}} {
        return
    }
    if {[catch {Apol_Progress_Dialog::wait "Open Database" "Opening $f" \
                    {apol_tcl_open_database $f} \
                } db] || $db == "NULL"} {
        tk_messageBox -icon error -type ok -title "Open Database" \
            -message [apol_tcl_get_info_string]
        return
    }

    if {$opts(db) != {}} {
        delete_sefs_fclist $opts(db)
    }
    _initializeVars
    set opts(db) $db
    set opts(fc_is_mls) [$db isMLS]
    set opts(indexFilename) $f
    if {[ApolTop::is_policy_open]} {
        $opts(db) associatePolicy $::ApolTop::policy
    }
}

proc Apol_File_Contexts::_search {} {
    variable opts
    variable widgets

    if {$opts(db) == {}} {
        tk_messageBox -icon error -type ok -title "File Contexts" -message "No database opened."
        return
    }
    Apol_Widget::clearSearchResults $widgets(results)
    if {$opts(useUser)} {
        if {[set user $opts(user)] == {}} {
            tk_messageBox -icon error -type ok -title "File Contexts" -message "No user selected."
            return
        }
    } else {
        set user {}
    }
    if {$opts(useRole)} {
        if {[set role $opts(role)] == {}} {
            tk_messageBox -icon error -type ok -title "File Contexts" -message "No user selected."
            return
        }
    } else {
        set role {}
    }
    if {$opts(useType)} {
        if {[set type $opts(type)] == {}} {
            tk_messageBox -icon error -type ok -title "File Contexts" -message "No type selected."
            return
        }
    } else {
        set type {}
    }
    if {$opts(fc_is_mls) && $opts(useRange)} {
        if {[set range $opts(range)] == {}} {
            tk_messageBox -icon error -type ok -title "File Contexts" -message "No MLS range selected."
            return
        }
    } else {
        set range {}
    }
    if {$opts(useObjclass)} {
        if {[set objclass $opts(objclass)] == {}} {
            tk_messageBox -icon error -type ok -title "File Contexts" -message "No object class selected."
            return
        }
    } else {
        set objclass {}
    }
    if {$opts(usePath)} {
        if {[set path $opts(path)] == {}} {
            tk_messageBox -icon error -type ok -title "File Contexts" -message "No path selected."
            return
        }
    } else {
        set path {}
    }

    set q [new_sefs_query]
    $q user $user
    $q role $role
    $q type $type 0
    $q range $range 0
    $q objectClass $objclass
    $q path $path
    $q regex $opts(useRegexp)

    if {[catch {Apol_Progress_Dialog::wait "File Contexts" "Searching database" \
                    {
                        set num_results [apol_tcl_query_database $opts(db) $q]
                        if {$num_results == 0} {
                            Apol_Widget::appendSearchResultText $widgets(results) "Search returned no results."
                        } else {
                            Apol_Widget::appendSearchResultHeader $widgets(results) "FILES FOUND ($num_results):\n\n"
                        }
                    }} err]} {
        tk_messageBox -icon error -type ok -title "File Contexts" -message $err
    }
    delete_sefs_query $q
}

proc Apol_File_Contexts::_search_callback {entry} {
    variable opts
    variable widgets
    set text {}
    if {$opts(showContext)} {
        set context [[$entry context] render NULL]
        append text [format "%-40s" $context]
    }
    if {$opts(showObjclass)} {
        set class [apol_objclass_to_str [$entry objectClass]]
        append text [format " %-12s" $class]
    }
    append text " [$entry path]\n"
    Apol_Widget::appendSearchResultText $widgets(results) $text
}

proc Apol_File_Contexts::_close_database {} {
    variable opts
    variable widgets
    if {$opts(db) != {}} {
        delete_sefs_fclist $opts(db)
    }
    _initializeVars
    Apol_Widget::clearSearchResults $widgets(results)
}

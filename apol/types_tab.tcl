# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets



##############################################################
# ::Apol_Types
#  
# The Types page
##############################################################
namespace eval Apol_Types {
    variable typelist {}
    variable attriblist {}
    variable opts
    variable widgets
}

proc Apol_Types::open { } {
    variable typelist {}
    variable attriblist {}

    foreach type_datum [apol_GetTypes {} 0] {
        lappend typelist [lindex $type_datum 0]
    }
    set typelist [lsort $typelist]
    foreach attrib_datum [apol_GetAttribs {} 0] {
        lappend attriblist [lindex $attrib_datum 0]
    }
    set attriblist [lsort $attriblist]
}

proc Apol_Types::close { } {
    variable widgets

    initializeVars
    set Apol_Types::typelist {}
    set Apol_Types::attriblist {}
    Apol_Widget::clearSearchResults $widgets(results)
}

proc Apol_Types::initializeVars {} {
    variable opts
    array set opts {
        types 1    types:show_attribs 1  types:show_aliases 1
        attribs 0  attribs:show_types 1  attribs:show_attribs 1
    }
}

proc Apol_Types::free_call_back_procs { } {
}

# ----------------------------------------------------------------------------------------
#  Command Apol_Types::set_Focus_to_Text
#
#  Description: 
# ----------------------------------------------------------------------------------------
proc Apol_Types::set_Focus_to_Text {} {
    focus $Apol_Types::widgets(results)
}

proc Apol_Types::popupTypeInfo {which ta} {
    set info_fc ""
    set index_file_loaded 0
    if {$which == "type"} {
        set info_ta [renderType [lindex [apol_GetTypes $ta] 0] 1 1]
    } else {
        set info_ta [renderAttrib [lindex [apol_GetAttribs $ta 0] 0] 1 0]
    }
    if {$ApolTop::libsefs == 1} {
        if {[Apol_File_Contexts::is_db_loaded]} {
            set rt [catch {set info_fc [Apol_File_Contexts::get_fc_files_for_ta $which $ta]} err]
            if {$rt != 0} {
                tk_messageBox -icon error -type ok -title "Error" \
                    -message "$err. \n\nIf you need to load an index file, go to the File Context tab."
                return -1
            }
            set index_file_loaded 1
        } 
    }
    set w .ta_infobox
    destroy $w

    toplevel $w 
    wm title $w $ta

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

    set b_close [button $bot_f.b_close -text "Close" -command [list destroy $w]]

    pack $top_f -side top -anchor nw -fill both -expand yes
    pack $bot_f -side bottom -anchor sw -fill x
    pack $b_close -side bottom -anchor center -expand 0 -pady 5
    pack $s_ta -fill both -expand yes
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
    wm protocol $w WM_DELETE_WINDOW [list destroy $w]
    raise $w
}

##############################################################
# ::search
#  	- Search text widget for a string
# 
proc Apol_Types::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_Types::searchTypes {} {
    variable widgets
    variable opts
	
    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }
    if {$opts(types) == 0 && $opts(attribs) == 0} {
        tk_messageBox -icon error -type ok -title "Error" -message "No search options provided!"
        return
    }
    set use_regexp [Apol_Widget::getRegexpEntryState $widgets(regexp)]
    set regexp [Apol_Widget::getRegexpEntryValue $widgets(regexp)]
    if {$use_regexp} {
        if {$regexp == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No regular expression provided."
            return
        }
    } else {
        set regexp {}
    }

    set results {}
    if {$opts(types)} {
        if {[catch {apol_GetTypes $regexp $use_regexp} types_data]} {
            tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining types list:\n$types_data"
            return
        }
        append results "TYPES ([llength $types_data]):\n\n"
        foreach t [lsort -index 0 $types_data] {
            append results "[renderType $t $opts(types:show_attribs) $opts(types:show_aliases)]\n"
        }
    }
    if {$opts(attribs)} {
        if {[catch {apol_GetAttribs $regexp $use_regexp} attribs_data]} {
            tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining types list:\n$attribs_data"
            return
        }
        if {$opts(types)} {
            append results "\n\n"
        }
        append results "ATTRIBUTES ([llength $attribs_data]):\n\n"
        foreach a [lsort -index 0 $attribs_data] {
            append results "[renderAttrib $a $opts(attribs:show_types) $opts(attribs:show_attribs)]\n"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_Types::renderType {type_datum show_attribs show_aliases} {
    set text ""
    foreach {type attribs aliases} $type_datum {break}
    append text "$type"
    if {$show_aliases && [llength $aliases] > 0} {
        append text " alias [list $aliases]"
    }
    if {$show_attribs} {
        append text " ([llength $attribs] attribute"
        if {[llength $attribs] != 1} {
            append text s
        }
        append text ")\n"
        foreach a [lsort $attribs] {
            append text "    $a\n"
        }
    }
    return $text
}

proc Apol_Types::renderAttrib {attrib_datum show_types show_attribs} {
    set text ""
    foreach {attrib types} $attrib_datum {break}
    append text "$attrib"
    if {$show_types} {
        append text " ([llength $types] type"
        if {[llength $types] != 1} {
            append text s
        }
        append text ")\n"
        foreach type [lsort $types] {
            append text "    $type"
            if {$show_attribs} {
                set a [lsort [lindex [apol_GetTypes $type] 0 1]]
                # remove the entry that we know should be there
                set idx [lsearch -sorted -exact $a $attrib]
                append text "  { [lreplace $a $idx $idx] }"
            }
            append text "\n"
        }
    }
    return $text
}

########################################################################
# ::goto_line
#  	- goes to indicated line in text box
# 
proc Apol_Types::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

proc Apol_Types::create {nb} {
    variable opts
    variable widgets

    initializeVars
    # Layout frames
    set frame [$nb insert end $ApolTop::types_tab -text "Types"]
    set pw1   [PanedWindow $frame.pw -side top]
    set left_pane   [$pw1 add -weight 0]
    set center_pane [$pw1 add -weight 1]
    set tpane [frame $left_pane.t]
    set apane [frame $left_pane.a]

    # Major subframes
    set tbox [TitleFrame $tpane.tbox -text "Types"]
    set abox [TitleFrame $apane.abox -text "Attributes"]
    set obox [TitleFrame $center_pane.obox -text "Search Options"]
    set rbox [TitleFrame $center_pane.rbox -text "Search Results"]

    # Placing layout frames and major subframes
    pack $obox -side top -expand 0 -fill both -padx 2
    pack $rbox -expand yes -fill both -padx 2
    pack $tbox -fill both -expand yes
    pack $abox -fill both -expand yes
    pack $pw1 -fill both -expand yes
    pack $tpane -fill both -expand 1
    pack $apane -fill both -expand 1
    
    # Types listbox
    set tlistbox [Apol_Widget::makeScrolledListbox [$tbox getframe].types \
                      -height 10 -width 20 -listvar Apol_Types::typelist]
    Apol_Widget::setListboxCallbacks $tlistbox \
        {{"Show Type Info" {Apol_Types::popupTypeInfo type}}}
    pack $tlistbox -expand 1 -fill both

    # Attributes listbox
    set alistbox [Apol_Widget::makeScrolledListbox [$abox getframe].attribs \
                      -height 5 -width 20 -listvar Apol_Types::attriblist]
    Apol_Widget::setListboxCallbacks $alistbox {{"Show Attribute Info" {Apol_Types::popupTypeInfo attrib}}}
    pack $alistbox -expand 1 -fill both

    # Search options section
    set ofm [$obox getframe]
    set fm_types_select [frame $ofm.to]
    set fm_attribs_select [frame $ofm.ao]
    pack $fm_types_select $fm_attribs_select -side left -padx 4 -pady 2 -anchor nw

    set types_select [checkbutton $fm_types_select.type -text "Show types" -variable Apol_Types::opts(types)]
    set typeattribs [checkbutton $fm_types_select.typeattribs -text "Include attributes" \
	-variable Apol_Types::opts(types:show_attribs)] 
    pack $types_select -anchor w
    pack $typeattribs -anchor w -padx 8
    trace add variable Apol_Types::opts(types) write \
        [list Apol_Types::toggleCheckbuttons $typeattribs]

    set attribs_select [checkbutton $fm_attribs_select.type -text "Show attributes" \
	-variable Apol_Types::opts(attribs)]
    set a_types [checkbutton $fm_attribs_select.types -text "Include types" \
	-variable Apol_Types::opts(attribs:show_types) -state disabled]
    set a_typeattribs [checkbutton $fm_attribs_select.typeattribs -text "Include types' attributes" \
	-variable Apol_Types::opts(attribs:show_attribs) -state disabled]
    pack $attribs_select -anchor w
    pack $a_types $a_typeattribs -anchor w -padx 8
    trace add variable Apol_Types::opts(attribs) write \
        [list Apol_Types::toggleCheckbuttons [list $a_typeattribs $a_types]]

    set widgets(regexp) [Apol_Widget::makeRegexpEntry $ofm.regexpf]
    Apol_Widget::setRegexpEntryState $widgets(regexp) 1

    pack $widgets(regexp) -side left -padx 4 -pady 2 -anchor nw

    set ok [button $ofm.ok -text OK -width 6 -command Apol_Types::searchTypes]
    pack $ok -side right -padx 5 -pady 5 -anchor ne
  
    # Display results window
    set widgets(results) [Apol_Widget::makeSearchResults [$rbox getframe].results]
    pack $widgets(results) -expand yes -fill both 

    return $frame
}

proc Apol_Types::toggleCheckbuttons {w name1 name2 op} {
    variable opts
    variable widgets
    if {$opts($name2)} {
        foreach x $w {
            $x configure -state normal
        }
    } else {
        foreach x $w {
            $x configure -state disabled
        }
    }
    if {!$opts(types) && !$opts(attribs)} {
        Apol_Widget::setRegexpEntryState $widgets(regexp) 0
    } else {
        Apol_Widget::setRegexpEntryState $widgets(regexp) 1
    }
}

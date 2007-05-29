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

namespace eval Apol_Types {
    variable typelist {}
    variable attriblist {}
    variable opts
    variable widgets
}

proc Apol_Types::create {tab_name nb} {
    variable opts
    variable widgets

    _initializeVars

    set frame [$nb insert end $tab_name -text "Types"]
    set pw1   [PanedWindow $frame.pw -side top]
    set left_pane   [$pw1 add -weight 0]
    set center_pane [$pw1 add -weight 1]
    set tpane [frame $left_pane.t]
    set apane [frame $left_pane.a]

    set tbox [TitleFrame $tpane.tbox -text "Types"]
    set abox [TitleFrame $apane.abox -text "Attributes"]
    set obox [TitleFrame $center_pane.obox -text "Search Options"]
    set rbox [TitleFrame $center_pane.rbox -text "Search Results"]

    pack $obox -side top -expand 0 -fill both -padx 2
    pack $rbox -expand yes -fill both -padx 2
    pack $tbox -fill both -expand yes
    pack $abox -fill both -expand yes
    pack $pw1 -fill both -expand yes
    pack $tpane -fill both -expand 1
    pack $apane -fill both -expand 1

    set tlistbox [Apol_Widget::makeScrolledListbox [$tbox getframe].types \
                      -height 10 -width 20 -listvar Apol_Types::typelist]
    Apol_Widget::setListboxCallbacks $tlistbox \
        {{"Show Type Info" {Apol_Types::_popupTypeInfo type}}}
    pack $tlistbox -expand 1 -fill both

    set alistbox [Apol_Widget::makeScrolledListbox [$abox getframe].attribs \
                      -height 5 -width 20 -listvar Apol_Types::attriblist]
    Apol_Widget::setListboxCallbacks $alistbox {{"Show Attribute Info" {Apol_Types::_popupTypeInfo attrib}}}
    pack $alistbox -expand 1 -fill both

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
        [list Apol_Types::_toggleCheckbuttons $typeattribs]

    set attribs_select [checkbutton $fm_attribs_select.type -text "Show attributes" \
	-variable Apol_Types::opts(attribs)]
    set a_types [checkbutton $fm_attribs_select.types -text "Include types" \
	-variable Apol_Types::opts(attribs:show_types) -state disabled]
    set a_typeattribs [checkbutton $fm_attribs_select.typeattribs -text "Include types' attributes" \
	-variable Apol_Types::opts(attribs:show_attribs) -state disabled]
    pack $attribs_select -anchor w
    pack $a_types $a_typeattribs -anchor w -padx 8
    trace add variable Apol_Types::opts(attribs) write \
        [list Apol_Types::_toggleCheckbuttons [list $a_typeattribs $a_types]]

    set widgets(regexp) [Apol_Widget::makeRegexpEntry $ofm.regexpf]
    Apol_Widget::setRegexpEntryState $widgets(regexp) 1

    pack $widgets(regexp) -side left -padx 4 -pady 2 -anchor nw

    set ok [button $ofm.ok -text OK -width 6 -command Apol_Types::_searchTypes]
    pack $ok -side right -padx 5 -pady 5 -anchor ne

    set widgets(results) [Apol_Widget::makeSearchResults [$rbox getframe].results]
    pack $widgets(results) -expand yes -fill both

    return $frame
}

proc Apol_Types::open {ppath} {
    set q [new_apol_type_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    variable typelist [lsort [type_vector_to_list $v]]
    $v -delete

    set q [new_apol_attr_query_t]
    set v [$q run $::ApolTop::policy]
    $q -delete
    variable attriblist [lsort [attr_vector_to_list $v]]
    $v -delete
}

proc Apol_Types::close {} {
    variable widgets

    _initializeVars
    set Apol_Types::typelist {}
    set Apol_Types::attriblist {}
    Apol_Widget::clearSearchResults $widgets(results)
}

proc Apol_Types::getTextWidget {} {
    variable widgets
    return $widgets(results).tb
}

# Given a type or alias name, return non-zero if that type/alias is
# within the policy.  If no policy has been loaded then return zero.
proc Apol_Types::isTypeInPolicy {type} {
    if {![ApolTop::is_policy_open]} {
        return 0
    }
    set q [new_apol_type_query_t]
    $q set_type $::ApolTop::policy $type
    set v [$q run $::ApolTop::policy]
    $q -delete
    if {$v == "NULL" || [$v get_size] == 0} {
        set retval 0
    } else {
        set retval 1
    }
    $v -delete
    set retval
}

# Given an attribute name, return non-zero if that attribute is within
# the loaded policy.  If no policy has been loaded then return zero.
proc Apol_Types::isAttributeInPolicy {attrib} {
    variable attriblist
    if {[ApolTop::is_policy_open] && [lsearch $attriblist $attrib] >= 0} {
        return 1
    }
    return 0
}

# Return a sorted list of all type names (not attributes nor aliases)
# within the current policy.  If no policy is open then return an
# empty list.
proc Apol_Types::getTypes {} {
    variable typelist
    set typelist
}

# Return a list of all attribute names within the current policy.  If
# no policy is open then return an empty list.
proc Apol_Types::getAttributes {} {
    variable attriblist
    set attriblist
}

#### private functions below ####

proc Apol_Types::_initializeVars {} {
    variable opts
    array set opts {
        types 1    types:show_attribs 1  types:show_aliases 1
        attribs 0  attribs:show_types 1  attribs:show_attribs 1
    }
}

proc Apol_Types::_toggleCheckbuttons {w name1 name2 op} {
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

proc Apol_Types::_popupTypeInfo {which ta} {
    set info_fc ""
    set index_file_loaded 0
    if {$which == "type"} {
        set info_ta [_renderType $ta 1 1]
    } else {
        set info_ta [_renderAttrib $ta 1 0]
    }
    if {[Apol_File_Contexts::is_db_loaded]} {
        set info_fc [Apol_File_Contexts::get_fc_files_for_ta $which $ta]
        set index_file_loaded 1
    }

    set w .ta_infobox
    destroy $w

    set w [Dialog .ta_infobox -cancel 0 -default 0 -modal none -parent . -separator 1 -title $ta]
    $w add -text "Close" -command [list destroy $w]

    set notebook [NoteBook [$w getframe].nb]
    pack $notebook -expand 1 -fill both

    set ta_info_tab [$notebook insert end ta_info_tab]
    set fc_info_tab [$notebook insert end fc_info_tab -text "Files"]

    if {$which == "type"} {
        $notebook itemconfigure ta_info_tab -text "Attributes"
    } else {
        $notebook itemconfigure ta_info_tab -text "Types"
    }
    set sw [ScrolledWindow [$notebook getframe ta_info_tab].sw -scrollbar both -auto both]
    set text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
    $sw setwidget $text
    pack $sw -expand 1 -fill both
    $text insert 0.0 $info_ta
    $text configure -state disabled

    if {$which != "type"} {
        set l [label [$notebook getframe fc_info_tab].l \
                   -text "Files labeled with types that are members of this attribute:" \
                   -justify left]
        pack $l -anchor nw
    }
    set sw [ScrolledWindow [$notebook getframe fc_info_tab].sw -scrollbar both -auto both]
    set text [text [$sw getframe].text -wrap none -font {helvetica 10} -bg white]
    $sw setwidget $text
    pack $sw -expand 1 -fill both

    $notebook raise [$notebook page 0]

    if {$index_file_loaded} {
        if {$info_fc != ""} {
            set num 0
            foreach item $info_fc {
                foreach {ctxt class path} $item {}
                $f_fc insert end "$ctxt\t     $class\t     $path\n"
                incr num
            }
            $text insert 1.0 "Number of files: $num\n\n"
        } else {
            $text insert end "No files found."
        }
    } else {
        $text insert 0.0 "No index file is loaded.  Load an index file through the File Context tab."
    }
    $text configure -state disabled

    $w draw {} 0 400x400
}

proc Apol_Types::_searchTypes {} {
    variable widgets
    variable opts

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened."
        return
    }
    if {$opts(types) == 0 && $opts(attribs) == 0} {
        tk_messageBox -icon error -type ok -title "Error" -message "No search options provided."
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
        set q [new_apol_type_query_t]
        $q set_type $::ApolTop::policy $regexp
        $q set_regex $::ApolTop::policy $use_regexp
        set v [$q run $::ApolTop::policy]
        $q -delete
        set types_data [type_vector_to_list $v]
        $v -delete
        append results "TYPES ([llength $types_data]):\n\n"
        foreach t [lsort $types_data] {
            append results "[_renderType $t $opts(types:show_attribs) $opts(types:show_aliases)]\n"
        }
    }
    if {$opts(attribs)} {
        set q [new_apol_attr_query_t]
        $q set_attr $::ApolTop::policy $regexp
        $q set_regex $::ApolTop::policy $use_regexp
        set v [$q run $::ApolTop::policy]
        $q -delete
        set attribs_data [attr_vector_to_list $v]
        $v -delete
        if {$opts(types)} {
            append results "\n\n"
        }
        append results "ATTRIBUTES ([llength $attribs_data]):\n\n"
        foreach a [lsort $attribs_data] {
            append results "[_renderAttrib $a $opts(attribs:show_types) $opts(attribs:show_attribs)]\n"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

proc Apol_Types::_renderType {type_name show_attribs show_aliases} {
    set qpol_type_datum [new_qpol_type_t $::ApolTop::qpolicy $type_name]
    set aliases {}
    set attribs {}
    set i [$qpol_type_datum get_alias_iter $::ApolTop::qpolicy]
    set aliases [iter_to_str_list $i]
    $i -delete
    set i [$qpol_type_datum get_attr_iter $::ApolTop::qpolicy]
    foreach a [iter_to_list $i] {
        set a [new_qpol_type_t $a]
        lappend attribs [$a get_name $::ApolTop::qpolicy]
    }
    $i -delete

    set text "$type_name"
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

proc Apol_Types::_renderAttrib {attrib_name show_types show_attribs} {
    set qpol_type_datum [new_qpol_type_t $::ApolTop::qpolicy $attrib_name]

    set text "$attrib_name"
    if {$show_types} {
        set types {}
        set i [$qpol_type_datum get_type_iter $::ApolTop::qpolicy]
        foreach t [iter_to_list $i] {
            set t [new_qpol_type_t $t]
            lappend types [$t get_name $::ApolTop::qpolicy]
        }
        $i -delete
        append text " ([llength $types] type"
        if {[llength $types] != 1} {
            append text s
        }
        append text ")\n"
        foreach type_name [lsort $types] {
            append text "    $type_name"
            if {$show_attribs} {
                set t [new_qpol_type_t $::ApolTop::qpolicy $type_name]
                set this_attribs {}
                set i [$t get_attr_iter $::ApolTop::qpolicy]
                foreach a [iter_to_list $i] {
                    set a [new_qpol_type_t $a]
                    lappend this_attribs [$a get_name $::ApolTop::qpolicy]
                }
                $i -delete

                set this_attribs [lsort $this_attribs]
                # remove the entry that we know should be there
                set idx [lsearch -sorted -exact $attrib_name $this_attribs]
                append text "  { [lreplace $this_attribs $idx $idx] }"
            }
            append text "\n"
        }
    }
    return $text
}

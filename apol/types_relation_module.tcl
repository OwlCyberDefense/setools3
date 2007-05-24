#  Copyright (C) 2004-2007 Tresys Technology, LLC
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

# This module implements the two types relationship analysis interface.

namespace eval Apol_Analysis_tra {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_tra" "Types Relationship Summary"
}

proc Apol_Analysis_tra::create {options_frame} {
    variable vals
    variable widgets

    _reinitializeVals

    set req_tf [TitleFrame $options_frame.req -text "Required Parameters"]
    pack $req_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    set fA [frame [$req_tf getframe].fA]
    pack $fA -side left -anchor nw -padx 2
    set lA [label $fA.l -text "Type A"]
    pack $lA -anchor w
    set widgets(typeA) [Apol_Widget::makeTypeCombobox $fA.t -width 19]
    pack $widgets(typeA)
    set fB [frame [$req_tf getframe].fB]
    pack $fB -side left -anchor nw -padx 2
    set lB [label $fB.l -text "Type B"]
    pack $lB -anchor w
    set widgets(typeB) [Apol_Widget::makeTypeCombobox $fB.t -width 19]
    pack $widgets(typeB)

    set basic_tf [TitleFrame $options_frame.basic -text "Basic Relationships"]
    pack $basic_tf -side left -padx 2 -pady 2 -expand 0 -fill y
    foreach {t a v} [list \
                       "Common attributes" attribs $::APOL_TYPES_RELATION_COMMON_ATTRIBS \
                       "Common roles" roles $::APOL_TYPES_RELATION_COMMON_ROLES \
                       "Common users" users $::APOL_TYPES_RELATION_COMMON_USERS \
                       "Similar access to resources" similars $::APOL_TYPES_RELATION_SIMILAR_ACCESS \
                       "Dissimilar access to resources" dissimilars $::APOL_TYPES_RELATION_DISSIMILAR_ACCESS \
                       "TE allow rules" allows $::APOL_TYPES_RELATION_ALLOW_RULES \
                       "Type transition/change rules" typerules $::APOL_TYPES_RELATION_TYPE_RULES] {
        set cb [checkbutton [$basic_tf getframe].$v -text $t \
                    -variable Apol_Analysis_tra::vals(run:$a) \
                    -onvalue $v -offvalue 0]
        pack $cb -anchor w
    }

    set an_tf [TitleFrame $options_frame.an -text "Analysis Relationships"]
    pack $an_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    foreach {t a v} [list \
                         "Direct flows between A and B" direct $::APOL_TYPES_RELATION_DIRECT_FLOW \
                         "Transitive flows A -> B" transAB $::APOL_TYPES_RELATION_TRANS_FLOW_AB \
                         "Transitive flows B -> A" transBA $::APOL_TYPES_RELATION_TRANS_FLOW_BA \
                         "Domain transitions A -> B" domainAB $::APOL_TYPES_RELATION_DOMAIN_TRANS_AB \
                         "Domain transitions B -> A" domainBA $::APOL_TYPES_RELATION_DOMAIN_TRANS_BA] {
        set cb [checkbutton [$an_tf getframe].$v -text $t \
                    -variable Apol_Analysis_tra::vals(run:$a) \
                    -onvalue $v -offvalue 0]
        pack $cb -anchor w
    }
}

proc Apol_Analysis_tra::open {} {
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(typeA)
    Apol_Widget::resetTypeComboboxToPolicy $widgets(typeB)
}

proc Apol_Analysis_tra::close {} {
    variable widgets
    _reinitializeVals
    _reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(typeA)
    Apol_Widget::clearTypeCombobox $widgets(typeB)
}

proc Apol_Analysis_tra::getInfo {} {
    return "The types relationship summary analysis in Apol is a convenience
mechanism to allow a user to quickly do several queries and analyses
already in present in Apol to understand the relationship between two
types.  This is meant to quickly display the relationship between two
types and therefore does not include all of the options present in the
standard queries and analyses.

\nFor additional help on this topic select \"Types Relationship Summary
Analysis\" from the help menu."
}

proc Apol_Analysis_tra::newAnalysis {} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    set results [_analyze]
    set f [_createResultsDisplay]
    _renderResults $f $results
    $results -delete
    return {}
}


proc Apol_Analysis_tra::updateAnalysis {f} {
    if {[set rt [_checkParams]] != {}} {
        return $rt
    }
    set results [_analyze]
    _clearResultsDisplay $f
    _renderResults $f $results
    $results -delete
    return {}
}

proc Apol_Analysis_tra::reset {} {
    _reinitializeVals
    _reinitializeWidgets
}

proc Apol_Analysis_tra::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    _reinitializeWidgets
}

proc Apol_Analysis_tra::saveQuery {channel} {
    variable vals
    variable widgets
    foreach {key value} [array get vals] {
        puts $channel "$key $value"
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(typeA)]
    puts $channel "typeA [lindex $type 0]"
    puts $channel "typeA:attrib [lindex $type 1]"
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(typeB)]
    puts $channel "typeB [lindex $type 0]"
    puts $channel "typeB:attrib [lindex $type 1]"
}

proc Apol_Analysis_tra::loadQuery {channel} {
    variable vals

    set classes_exc {}
    set subjects_exc {}
    while {[gets $channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        set key {}
        set value {}
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
        set vals($key) $value
    }
    _reinitializeWidgets
}

proc Apol_Analysis_tra::getTextWidget {tab} {
    return [$tab.right getframe].res
}


#################### private functions below ####################

proc Apol_Analysis_tra::_reinitializeVals {} {
    variable vals

    set vals(run:attribs) $::APOL_TYPES_RELATION_COMMON_ATTRIBS
    set vals(run:roles) $::APOL_TYPES_RELATION_COMMON_ROLES
    set vals(run:users) $::APOL_TYPES_RELATION_COMMON_USERS
    array set vals {
        typeA {}  typeA:attrib {}
        typeB {}  typeB:attrib {}

        run:similars 0
        run:dissimilars 0
        run:allows 0
        run:typerules 0

        run:direct 0
        run:transAB 0
        run:transBA 0
        run:domainAB 0
        run:domainBA 0
    }
}

proc Apol_Analysis_tra::_reinitializeWidgets {} {
    variable vals
    variable widgets

    if {$vals(typeA:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(typeA) [list $vals(typeA) $vals(typeA:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(typeA) $vals(typeA)
    }
    if {$vals(typeB:attrib) != {}} {
        Apol_Widget::setTypeComboboxValue $widgets(typeB) [list $vals(typeB) $vals(typeB:attrib)]
    } else {
        Apol_Widget::setTypeComboboxValue $widgets(typeB) $vals(typeB)
    }
}

#################### functions that do analyses ####################

proc Apol_Analysis_tra::_checkParams {} {
    variable vals
    variable widgets
    if {![ApolTop::is_policy_open]} {
        return "No current policy file is opened."
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(typeA)]
    if {[lindex $type 0] == {}} {
        return "No type was selected for type A."
    }
    if {![Apol_Types::isTypeInPolicy [lindex $type 0]]} {
        return "[lindex $type 0] is not a type within the policy."
    }
    set vals(typeA) [lindex $type 0]
    set vals(typeA:attrib) [lindex $type 1]
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(typeB)]
    if {[lindex $type 0] == {}} {
        return "No type was selected for type B."
    }
    if {![Apol_Types::isTypeInPolicy [lindex $type 0]]} {
        return "[lindex $type 0] is not a type within the policy."
    }
    set vals(typeB) [lindex $type 0]
    set vals(typeB:attrib) [lindex $type 1]
    set analysis_selected 0
    foreach key [array names vals run:*] {
        if {$vals($key)} {
            # if a permap is not loaded then load the default permap
            if {($key == "run:direct" || [string match run:trans* $key]) && \
                    ![Apol_Perms_Map::is_pmap_loaded]} {
                if {![ApolTop::openDefaultPermMap]} {
                    return "This analysis requires that a permission map is loaded."
                }
                apol_tcl_clear_info_string
            }
            set analysis_selected 1
        }
    }
    if {!$analysis_selected} {
        return "At least one analysis must be selected."
    }
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_tra::_analyze {} {
    variable vals
    set q [new_apol_types_relation_analysis_t]
    $q set_first_type $::ApolTop::policy $vals(typeA)
    $q set_other_type $::ApolTop::policy $vals(typeB)
    set analyses 0
    foreach key [array names vals run:*] {
        set analyses [expr {$analyses | $vals($key)}]
    }
    $q set_analyses $::ApolTop::policy $analyses

    set results [$q run $::ApolTop::policy]
    $q -delete
    return $results
}

################# functions that control analysis output #################

proc Apol_Analysis_tra::_createResultsDisplay {} {
    variable vals

    set f [Apol_Analysis::createResultTab "Types Relationship" [array get vals]]

    set tree_tf [TitleFrame $f.left -text "Types Relationship Results"]
    pack $tree_tf -side left -expand 0 -fill y -padx 2 -pady 2
    set sw [ScrolledWindow [$tree_tf getframe].sw -auto both]
    set tree [Tree [$sw getframe].tree -width 24 -redraw 1 -borderwidth 0 \
                  -highlightthickness 0 -showlines 1 -padx 0 -bg white]
    $sw setwidget $tree
    pack $sw -expand 1 -fill both

    set res_tf [TitleFrame $f.right -text "Types Relationship Information"]
    pack $res_tf -side left -expand 1 -fill both -padx 2 -pady 2
    set res [Apol_Widget::makeSearchResults [$res_tf getframe].res]
    $res.tb tag configure title -font {Helvetica 14 bold}
    $res.tb tag configure title_type -foreground blue -font {Helvetica 14 bold}
    $res.tb tag configure subtitle -font {Helvetica 10 bold}
    $res.tb tag configure subtitle_dir -foreground blue -font {Helvetica 10 bold}
    $res.tb tag configure num -foreground blue -font {Helvetica 10 bold}
    pack $res -expand 1 -fill both

    update
    grid propagate $sw 0
    $tree configure -selectcommand [list Apol_Analysis_tra::_treeSelect $res]
    return $f
}

proc Apol_Analysis_tra::_treeSelect {res tree node} {
    if {$node != {}} {
        $res.tb configure -state normal
        $res.tb delete 0.0 end
        set data [$tree itemcget $node -data]
        set name [$tree itemcget $node -text]
        if {[set parent [$tree parent $node]] != "root"} {
            set parent_name [$tree itemcget $parent -text]
            set parent_data [$tree itemcget $parent -data]
        }
        switch -glob -- $node {
            pre:* {
                # an informational node, whose data has already been rendered
                eval $res.tb insert end $data
            }
            simtitle {
                _showSimilarTitle $res $data
            }
            sim:* {
                _showSimilar $res $name $parent_data $data
            }
            distitle {
                _showDissimilarTitle $res $data
            }
            dissubtitle* {
                _showDissimilarSubtitle $res $data
            }
            dis:* {
                _showDissimilar $res $name $parent_name $data
            }
            allow {
                _showAllows $res $data
            }
            typerules {
                _showTypeRules $res $data
            }
            x* {
                _showDirectFlow $res $data
            }
            y* {
                _showTransFlow $res $data
            }
            f:* {
                _showDTA $res $data
            }
        }
        $res.tb configure -state disabled
    }
}

proc Apol_Analysis_tra::_clearResultsDisplay {f} {
    variable vals
    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_tra::_renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    if {$vals(run:attribs)} {
        _renderCommon Attributes $tree $results get_attributes attr_vector_to_list
    }
    if {$vals(run:roles)} {
        _renderCommon Roles $tree $results get_roles role_vector_to_list
    }
    if {$vals(run:users)} {
        _renderCommon Users $tree $results get_users user_vector_to_list
    }
    if {$vals(run:similars)} {
        _renderSimilars $tree $results
    }
    if {$vals(run:dissimilars)} {
        _renderDissimilars $tree $results
    }
    if {$vals(run:allows)} {
        _renderAllows $tree $results
    }
    if {$vals(run:typerules)} {
        _renderTypeRules $tree $results
    }
    if {$vals(run:direct)} {
        _renderDirectFlow $tree $results
    }
    if {$vals(run:transAB)} {
        _renderTransFlow 0 $tree $results
    }
    if {$vals(run:transBA)} {
        _renderTransFlow 1 $tree $results
    }
    if {$vals(run:domainAB)} {
        _renderDTA 0 $tree $results
    }
    if {$vals(run:domainBA)} {
        _renderDTA 1 $tree $results
    }
    set first_node [$tree nodes root 0]
    $tree selection set $first_node
    $tree see $first_node
}

proc Apol_Analysis_tra::_renderCommon {title tree results func convert_func} {
    set names [$convert_func [$results $func]]
    set text [list "Common $title ([llength $names]):\n\n" title]
    foreach n [lsort $names] {
        lappend text "$n\n" {}
    }
    $tree insert end root pre:$title -text "Common $title" -data $text
}

# Convert a vector of apol_types_relation_access_t pointers into a
# list of access tuples.  Each tuple is:
#
#   type name
#   list of avrules
proc Apol_Analysis_tra::_types_relation_access_vector_to_list {v} {
    set l {}
    for {set i 0} {$v != "NULL" && $i < [$v get_size]} {incr i} {
        set a [new_apol_types_relation_access_t [$v get_element $i]]
        set type [[$a get_type] get_name $::ApolTop::qpolicy]
        set rules [avrule_vector_to_list [$a get_rules]]
        lappend l [list $type $rules]
    }
    set l
}

proc Apol_Analysis_tra::_renderSimilars {tree results} {
    variable vals
    set simA [_types_relation_access_vector_to_list [$results get_similar_first]]
    set simB [_types_relation_access_vector_to_list [$results get_similar_other]]
    set data [list $vals(typeA) $vals(typeB) [llength $simA]]
    $tree insert end root simtitle -text "Similar access to resources" -data $data -drawcross allways
    foreach accessA [lsort -index 0 $simA] accessB [lsort -index 0 $simB] {
        set type [lindex $accessA 0]
        set rulesA [lindex $accessA 1]
        set rulesB [lindex $accessB 1]
        $tree insert end simtitle sim:$type -text $type -data [list $rulesA $rulesB]
    }
}

proc Apol_Analysis_tra::_showSimilarTitle {res data} {
    foreach {typeA typeB numTypes} $data {break}
    $res.tb insert end $typeA title_type \
        " and " title \
        $typeB title_type \
        " access $numTypes common type(s).\n\n" title \
        "Open the subtree for this item to see the list of common types that
can be accessed.  You may then select a type from the subtree to see
the allow rules which provide the access." {}
}

proc Apol_Analysis_tra::_showSimilar {res name parent_data data} {
    foreach {typeA typeB} $parent_data {rulesA rulesB} $data {break}
    $res.tb insert end $typeA title_type \
        " accesses " title \
        $name title_type \
        ":\n\n" title
    set v [new_apol_vector_t]
    foreach r $rulesA {
        $v append $r
    }
    apol_tcl_avrule_sort $::ApolTop::policy $v
    Apol_Widget::appendSearchResultRules $res 2 $v new_qpol_avrule_t
    $v -delete

    $res.tb insert end "\n" title \
        $typeB title_type \
        " accesses " title \
        $name title_type \
        ":\n\n" title
    set v [new_apol_vector_t]
    foreach r $rulesB {
        $v append $r
    }
    apol_tcl_avrule_sort $::ApolTop::policy $v
    Apol_Widget::appendSearchResultRules $res 2 $v new_qpol_avrule_t
    $v -delete
}

proc Apol_Analysis_tra::_renderDissimilars {tree results} {
    variable vals
    set disA [_types_relation_access_vector_to_list [$results get_dissimilar_first]]
    set disB [_types_relation_access_vector_to_list [$results get_dissimilar_other]]
    set data [list $vals(typeA) $vals(typeB)]
    $tree insert end root distitle -text "Dissimilar access to resources" -data $data

    set data [list $vals(typeA) $vals(typeB) [llength $disA]]
    $tree insert end distitle dissubtitleA -text $vals(typeA) -data $data -drawcross allways
    foreach access [lsort -index 0 $disA] {
        set type [lindex $access 0]
        set rules [lindex $access 1]
        $tree insert end dissubtitleA dis:$type -text $type -data $rules
    }
    set data [list $vals(typeB) $vals(typeA) [llength $disB]]
    $tree insert end distitle dissubtitleB -text $vals(typeB) -data $data -drawcross allways
    foreach access [lsort -index 0 $disB] {
        set type [lindex $access 0]
        set rules [lindex $access 1]
        $tree insert end dissubtitleB dis:$type -text $type -data $rules
    }
}

proc Apol_Analysis_tra::_showDissimilarTitle {res data} {
    foreach {typeA typeB} $data {break}
    $res.tb insert end "Dissimilar access between " title \
        $typeA title_type \
        " and " title \
        $typeB title_type \
        ".\n\n" title \
        "Open the subtree for this item to access individual subtrees of types
which can be accessed by one type but not the other.  You may then
select a type from a subtree to see the allow rules which provide the
access." {}
}

proc Apol_Analysis_tra::_showDissimilarSubtitle {res data} {
    foreach {one_type other_type numTypes} $data {break}
    $res.tb insert end $one_type title_type \
        " accesss $numTypes type(s) to which " title \
        $other_type title_type \
        " does not have access.\n\n" title \
        "Open the subtree for this item to see the list of types.  You may then
select a type from the subtree to see the allow rules which provide
the access." {}
}

proc Apol_Analysis_tra::_showDissimilar {res name parent_name data} {
    $res.tb insert end $parent_name title_type \
        " accesses " title \
        $name title_type \
        ":\n\n" title
    set v [new_apol_vector_t]
    foreach r $data {
        $v append $r
    }
    apol_tcl_avrule_sort $::ApolTop::policy $v
    Apol_Widget::appendSearchResultRules $res 2 $v new_qpol_avrule_t
    $v -delete
}

proc Apol_Analysis_tra::_renderAllows {tree results} {
    set rules [$results get_allowrules]
    set rules_dup [new_apol_vector_t $rules]
    $rules_dup -acquire
    apol_tcl_avrule_sort $::ApolTop::policy $rules_dup
    $tree insert end root allow -text "TE Allow Rules" -data $rules_dup
}

proc Apol_Analysis_tra::_showAllows {res data} {
    $res.tb insert end "TE Allow Rules ([$data get_size]):\n\n" title
    Apol_Widget::appendSearchResultRules $res 2 $data new_qpol_avrule_t
}

proc Apol_Analysis_tra::_renderTypeRules {tree results} {
    set rules [$results get_typerules]
    set rules_dup [new_apol_vector_t $rules]
    apol_tcl_terule_sort $::ApolTop::policy $rules_dup
    $rules_dup -acquire
    $tree insert end root typerules -text "Type Transition/Change Rules" -data $rules_dup
}

proc Apol_Analysis_tra::_showTypeRules {res data} {
    $res.tb insert end "Type transition/change rules ([$data get_size]):\n\n" title
    Apol_Widget::appendSearchResultRules $res 2 $data new_qpol_terule_t
}

proc Apol_Analysis_tra::_renderDirectFlow {tree results} {
    set v [$results get_directflows]
    if {$v == "NULL" || [$v get_size] == 0} {
        $tree insert end root pre:direct
        set node [$tree nodes root end]
        set data [list "No direct information flows found." title]
    } else {
        variable vals
        Apol_Analysis_directflow::appendResultsNodes $tree root $v
        set node [$tree nodes root end]
        set data [list $vals(typeA) $vals(typeB) [$tree itemcget $node -data]]
    }
    $tree itemconfigure $node -text "Direct Flows Between A and B" -data $data -drawcross auto
}

proc Apol_Analysis_tra::_showDirectFlow {res data} {
    foreach {parent_name name data} $data {break}
    foreach {flow_dir classes} [lindex $data 1] {break}
    $res.tb insert end "Information flows both into and out of " title \
        $parent_name title_type \
        " from/to " title \
        $name title_type
    $res.tb insert end "\n\n" title_type \
        "Objects classes for " subtitle \
        [string toupper $flow_dir] subtitle_dir \
        " flows:\n" subtitle
    foreach c $classes {
        foreach {class_name rules} $c {break}
        $res.tb insert end "      " {} \
            $class_name\n subtitle
        set v [new_apol_vector_t]
        foreach r $rules {
            $v append $r
        }
        apol_tcl_avrule_sort $::ApolTop::policy $v
        Apol_Widget::appendSearchResultRules $res 12 $v new_qpol_avrule_t
        $v -delete
    }
}

proc Apol_Analysis_tra::_renderTransFlow {dir tree results} {
    variable vals
    if {$dir == 0} {
        set title2 "A->B"
        set v [$results get_transflowsAB]
        set data [list $vals(typeB) $vals(typeA)]
    } else {
        set title2 "B->A"
        set v [$results get_transflowsBA]
        set data [list $vals(typeA) $vals(typeB)]
    }
    if {$v == "NULL" || [$v get_size] == 0} {
        $tree insert end root pre:trans$dir
        set node [$tree nodes root end]
        set data [list "No transitive information flows found." title]
    } else {
        Apol_Analysis_transflow::appendResultsNodes $tree root $v
        set node [$tree nodes root end]
        lappend data [$tree itemcget $node -data]
    }
    $tree itemconfigure $node -text "Transitive Flows $title2" -data $data -drawcross auto
}

proc Apol_Analysis_tra::_showTransFlow {res data} {
    foreach {parent_name name data} $data {break}
    foreach {flow_dir paths} [lindex $data 1] {break}
    $res.tb insert end "Information flows from " title \
        $name title_type \
        " to " title \
        $parent_name title_type
    $res.tb insert end "\n\n" title \
        "Apol found the following number of information flows: " subtitle \
        [llength $paths] num \
        "\n" subtitle
    set path_num 1
    foreach path $paths {
        $res.tb insert end "\n" {}
        Apol_Analysis_transflow::renderPath $res $path_num $path
        incr path_num
    }
}

proc Apol_Analysis_tra::_renderDTA {dir tree dta} {
    variable vals
    if {$dir == 0} {
        set title2 "A->B"
        set data [list $vals(typeA) $vals(typeB)]
    } else {
        set title2 "B->A"
        set data [list $vals(typeB) $vals(typeA)]
    }
    if {$dta == {}} {
        $tree insert end root pre:dta$dir
        set node [$tree nodes root end]
        set data [list "No domain transitions found." title]
    } else {
        Apol_Analysis_domaintrans::createResultsNodes $tree root $dta forward
        set node [$tree nodes root end]
        lappend data [$tree itemcget $node -data]
    }
    $tree itemconfigure $node -text "Domain Transitions $title2" -data $data -drawcross auto
}

proc Apol_Analysis_tra::_showDTA {res data} {
    foreach {parent_name name data} $data {break}
    foreach {proctrans setexec ep access_list} [lindex $data 1] {break}
    set header [list "Domain transition from " title \
                    $parent_name title_type \
                    " to " title \
                    $name title_type]
    eval $res.tb insert end $header
    $res.tb insert end "\n\n" title_type

    $res.tb insert end "Process Transition Rules: " subtitle \
        [llength $proctrans] num \
        "\n" subtitle
    Apol_Widget::appendSearchResultAVRules $res 6 $proctrans
    if {[llength $setexec] > 0} {
        $res.tb insert end "\n" {} \
            "Setexec Rules: " subtitle \
            [llength $setexec] num \
            "\n" subtitle
        Apol_Widget::appendSearchResultAVRules $res 6 $setexec
    }
    $res.tb insert end "\nEntry Point File Types: " subtitle \
        [llength $ep] num
    foreach e [lsort -index 0 $ep] {
        foreach {intermed entrypoint execute type_trans} $e {break}
        $res.tb insert end "\n      $intermed\n" {} \
            "            " {} \
            "File Entrypoint Rules: " subtitle \
            [llength $entrypoint] num \
            "\n" subtitle
        Apol_Widget::appendSearchResultAVRules $res 12 $entrypoint
        $res.tb insert end "\n" {} \
            "            " {} \
            "File Execute Rules: " subtitle \
            [llength $execute] num \
            "\n" subtitle
        Apol_Widget::appendSearchResultAVRules $res 12 $execute
        if {[llength $type_trans] > 0} {
            $res.tb insert end "\n" {} \
                "            " {} \
                "Type_transition Rules: " subtitle \
                [llength $type_trans] num \
                "\n" subtitle
            Apol_Widget::appendSearchResultTERules $res 12 $type_trans
        }
    }
    if {[llength $access_list] > 0} {
        $res.tb insert end "\n" {} \
            "The access filters you specified returned the following rules: " subtitle \
            [llength $access_list] num \
            "\n" subtitle
        Apol_Widget::appendSearchResultAVRule $res 6 $access_list
    }
}

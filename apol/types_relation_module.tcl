#############################################################
#  types_relation_module.tcl
# -----------------------------------------------------------
#  Copyright (C) 2004-2006 Tresys Technology, LLC
#  see file 'COPYING' for use and warranty information
#
#  Requires tcl and tk 8.4+, with BWidget
#  Author: <don.patterson@tresys.com> 8-11-2004
# -----------------------------------------------------------
#
# This module implements the two types relationship analysis interface.

namespace eval Apol_Analysis_tra {
    variable vals
    variable widgets
    Apol_Analysis::registerAnalysis "Apol_Analysis_tra" "Types Relationship Summary"
}

proc Apol_Analysis_tra::open {} {
    variable widgets
    Apol_Widget::resetTypeComboboxToPolicy $widgets(typeA)
    Apol_Widget::resetTypeComboboxToPolicy $widgets(typeB)
}

proc Apol_Analysis_tra::close {} {
    variable widgets
    reinitializeVals
    reinitializeWidgets
    Apol_Widget::clearTypeCombobox $widgets(typeA)
    Apol_Widget::clearTypeCombobox $widgets(typeB)
}

proc Apol_Analysis_tra::getInfo {} {
    return "The types relationship summary analysis in Apol is a convenience
mechanism to allow a user to quickly do several queries and analyses
already in present in Apol to understand the relationship between two
types.  This is meant to quickly display the relationship between two
types and therefore doesn't include all of the options present in the
standard queries and analyses.

\nFor additional help on this topic select \"Types Relationship Summary
Analysis\" from the help menu."
}

proc Apol_Analysis_tra::create {options_frame} {
    variable vals
    variable widgets

    reinitializeVals

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
    foreach {t v} {"Common attributes" attribs \
                       "Common roles" roles \
                       "Common users" users \
                       "Similar access to resources" similars \
                       "Dissimilar access to resources" dissimilars
                       "TE allow rules" allows \
                       "Type transition/change rules" typerules} {
        set cb [checkbutton [$basic_tf getframe].$v -text $t \
                    -variable Apol_Analysis_tra::vals(run:$v)]
        pack $cb -anchor w
    }

    set an_tf [TitleFrame $options_frame.an -text "Analysis Relationships"]
    pack $an_tf -side left -padx 2 -pady 2 -expand 1 -fill both
    foreach {t v} {"Direct flows between A and B" direct \
                       "Transitive flows A -> B" transAB \
                       "Transitive flows B -> A" transBA \
                       "Domain transitions A -> B" domainAB \
                       "Domain transitions B -> A" domainBA} {
        set cb [checkbutton [$an_tf getframe].$v -text $t \
                    -variable Apol_Analysis_tra::vals(run:$v)]
        pack $cb -anchor w
    }
}

proc Apol_Analysis_tra::newAnalysis {} {
    if {[set rt [checkParams]] != {}} {
        return $rt
    }
    if {[catch {analyze} results]} {
        return $results
    }
    set f [createResultsDisplay]
    if {[catch {renderResults $f $results} rt]} {
        Apol_Analysis::deleteCurrentResults
        return $rt
    }
    return {}
}


proc Apol_Analysis_tra::updateAnalysis {f} {
    if {[set rt [checkParams]] != {}} {
        return $rt
    }
    if {[catch {analyze} results]} {
        return $results
    }
    clearResultsDisplay $f
    if {[catch {renderResults $f $results} rt]} {
        return $rt
    }
    return {}
}

proc Apol_Analysis_tra::reset {} {
    reinitializeVals
    reinitializeWidgets
}

proc Apol_Analysis_tra::switchTab {query_options} {
    variable vals
    variable widgets
    array set vals $query_options
    reinitializeWidgets
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
    reinitializeWidgets
}

proc Apol_Analysis_tra::gotoLine {tab line_num} {
}

proc Apol_Analysis_tra::search {tab str case_Insensitive regExpr srch_Direction } {
}


#################### private functions below ####################

proc Apol_Analysis_tra::reinitializeVals {} {
    variable vals

    array set vals {
        typeA {}  typeA:attrib {}
        typeB {}  typeB:attrib {}

        run:attribs 1
        run:roles 1
        run:users 1
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

proc Apol_Analysis_tra::reinitializeWidgets {} {
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

proc Apol_Analysis_tra::checkParams {} {
    variable vals
    variable widgets
    if {![ApolTop::is_policy_open]} {
        return "No current policy file is opened!"
    }
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(typeA)]
    if {[lindex $type 0] == {}} {
        return "No type was selected for type A."
    }
    set vals(typeA) [lindex $type 0]
    set vals(typeA:attrib) [lindex $type 1]
    set type [Apol_Widget::getTypeComboboxValueAndAttrib $widgets(typeB)]
    if {[lindex $type 0] == {}} {
        return "No type was selected for type B."
    }
    set vals(typeB) [lindex $type 0]
    set vals(typeB:attrib) [lindex $type 1]
    set analysis_selected 0
    foreach key [array names vals run:*] {
        if {$vals($key)} {
            # if a permap is not loaded then load the default permap
            if {($key == "run:direct" || [string match run:trans* $key]) && \
                    ![Apol_Perms_Map::is_pmap_loaded]} {
                if {![Apol_Perms_Map::loadDefaultPermMap]} {
                    return "This analysis requires that a permission map is loaded."
                }
            }
            set analysis_selected 1
        }
    }
    if {!$analysis_selected} {
        return "At least one analysis must be selected."
    }
    return {}  ;# all parameters passed, now ready to do search
}

proc Apol_Analysis_tra::analyze {} {
    variable vals
    set analyses {}
    foreach key [array names vals run:*] {
        if {$vals($key)} {
            lappend analyses [lindex [split $key :] 1]
        }
    }
    apol_TypesRelationshipAnalysis $vals(typeA) $vals(typeB) $analyses
}

################# functions that control analysis output #################

proc Apol_Analysis_tra::createResultsDisplay {} {
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
    $tree configure -selectcommand [list Apol_Analysis_tra::treeSelect $res]
    return $f
}

proc Apol_Analysis_tra::treeSelect {res tree node} {
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
                showSimilarTitle $res $data
            }
            sim:* {
                showSimilar $res $name $parent_data $data
            }
            distitle {
                showDissimilarTitle $res $data
            }
            dissubtitle* {
                showDissimilarSubtitle $res $data
            }
            dis:* {
                showDissimilar $res $name $parent_name $data
            }
            allow {
                showAllows $res $data
            }
            typerules {
                showTypeRules $res $data
            }
            x* {
                showDirectFlow $res $data
            }
            y* {
                showTransFlow $res $data
            }
            f:* {
                showDTA $res $data
            }
        }
        $res.tb configure -state disabled
    }
}

proc Apol_Analysis_tra::clearResultsDisplay {f} {
    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    $tree delete [$tree nodes root]
    Apol_Widget::clearSearchResults $res
    Apol_Analysis::setResultTabCriteria [array get vals]
}

proc Apol_Analysis_tra::renderResults {f results} {
    variable vals

    set tree [[$f.left getframe].sw getframe].tree
    set res [$f.right getframe].res
    foreach {attribs roles users similars dissimilars allows typerules \
        dirflow transAB transBA domsAB domsBA} $results {break}
    if {$vals(run:attribs)} {
        renderCommon Attributes $tree $attribs
    }
    if {$vals(run:roles)} {
        renderCommon Roles $tree $roles
    }
    if {$vals(run:users)} {
        renderCommon Users $tree $users
    }
    if {$vals(run:similars)} {
        renderSimilars $tree $similars
    }
    if {$vals(run:dissimilars)} {
        renderDissimilars $tree $dissimilars
    }
    if {$vals(run:allows)} {
        renderAllows $tree $allows
    }
    if {$vals(run:typerules)} {
        renderTypeRules $tree $typerules
    }
    if {$vals(run:direct)} {
        renderDirectFlow $tree $dirflow
    }
    if {$vals(run:transAB)} {
        renderTransFlow 0 $tree $transAB
    }
    if {$vals(run:transBA)} {
        renderTransFlow 1 $tree $transBA
    }
    if {$vals(run:domainAB)} {
        renderDTA 0 $tree $domsAB
    }
    if {$vals(run:domainBA)} {
        renderDTA 1 $tree $domsBA
    }
    set first_node [$tree nodes root 0]
    $tree selection set $first_node
    update idletasks
    $tree see $first_node
}

proc Apol_Analysis_tra::renderCommon {title tree names} {
    set text [list "Common $title ([llength $names]):\n\n" title]
    foreach n [lsort $names] {
        lappend text "$n\n" {}
    }
    $tree insert end root pre:$title -text "Common $title" -data $text
}

proc Apol_Analysis_tra::renderSimilars {tree results} {
    variable vals
    foreach {simA simB} $results {break}
    set data [list $vals(typeA) $vals(typeB) [llength $simA]]
    $tree insert end root simtitle -text "Similar access to resources" -data $data -drawcross allways
    foreach accessA [lsort -index 0 $simA] accessB [lsort -index 0 $simB] {
        set type [lindex $accessA 0]
        set rulesA [lindex $accessA 1]
        set rulesB [lindex $accessB 1]
        $tree insert end simtitle sim:$type -text $type -data [list $rulesA $rulesB]
    }
}

proc Apol_Analysis_tra::showSimilarTitle {res data} {
    foreach {typeA typeB numTypes} $data {break}
    $res.tb insert end $typeA title_type \
        " and " title \
        $typeB title_type \
        " access $numTypes common type(s).\n\n" title \
        "Open the subtree for this item to see the list of common types that
can be accessed.  You may then select a type from the subtree to see
the allow rules which provide the access." {}
}

proc Apol_Analysis_tra::showSimilar {res name parent_data data} {
    foreach {typeA typeB} $parent_data {rulesA rulesB} $data {break}
    $res.tb insert end $typeA title_type \
        " accesses " title \
        $name title_type \
        ":\n\n" title
    Apol_Widget::appendSearchResultAVRules $res 2 $rulesA
    $res.tb insert end "\n" title \
        $typeB title_type \
        " accesses " title \
        $name title_type \
        ":\n\n" title
    Apol_Widget::appendSearchResultAVRules $res 2 $rulesB
}

proc Apol_Analysis_tra::renderDissimilars {tree results} {
    variable vals
    foreach {disA disB} $results {break}
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

proc Apol_Analysis_tra::showDissimilarTitle {res data} {
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

proc Apol_Analysis_tra::showDissimilarSubtitle {res data} {
    foreach {one_type other_type numTypes} $data {break}
    $res.tb insert end $one_type title_type \
        " accesss $numTypes type(s) to which " title \
        $other_type title_type \
        " does not have access.\n\n" title \
        "Open the subtree for this item to see the list of types.  You may then
select a type from the subtree to see the allow rules which provide
the access." {}
}

proc Apol_Analysis_tra::showDissimilar {res name parent_name data} {
    $res.tb insert end $parent_name title_type \
        " accesses " title \
        $name title_type \
        ":\n\n" title
    Apol_Widget::appendSearchResultAVRules $res 2 $data
}

proc Apol_Analysis_tra::renderAllows {tree rules} {
    $tree insert end root allow -text "TE Allow Rules" -data $rules
}

proc Apol_Analysis_tra::showAllows {res data} {
    $res.tb insert end "TE Allow Rules ([llength $data]):\n\n" title
    Apol_Widget::appendSearchResultAVRules $res 2 $data
}

proc Apol_Analysis_tra::renderTypeRules {tree rules} {
    $tree insert end root typerules -text "Type Transition/Change Rules" -data $rules
}

proc Apol_Analysis_tra::showTypeRules {res data} {
    $res.tb insert end "Type transition/change rules ([llength $data]):\n\n" title
    foreach r $data {
         Apol_Widget::appendSearchResultTERules $res 2 $r
    }
}

proc Apol_Analysis_tra::renderDirectFlow {tree dirflows} {
    if {$dirflows == {}} {
        $tree insert end root pre:direct
        set node [$tree nodes root end]
        set data [list "No direct information flows found." title]
    } else {
        variable vals
        Apol_Analysis_directflow::createResultsNodes $tree root $dirflows 0
        set node [$tree nodes root end]
        set data [list $vals(typeA) $vals(typeB) [$tree itemcget $node -data]]
    }
    $tree itemconfigure $node -text "Direct Flows Between A and B" -data $data -drawcross auto
}

proc Apol_Analysis_tra::showDirectFlow {res data} {
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
        Apol_Widget::appendSearchResultAVRules $res 12 $rules
    }
}

proc Apol_Analysis_tra::renderTransFlow {dir tree transflows} {
    variable vals
    if {$dir == 0} {
        set title2 "A->B"
        set data [list $vals(typeB) $vals(typeA)]
    } else {
        set title2 "B->A"
        set data [list $vals(typeA) $vals(typeB)]
    }
    if {$transflows == {}} {
        $tree insert end root pre:trans$dir
        set node [$tree nodes root end]
        set data [list "No transitive information flows found." title]
    } else {
        Apol_Analysis_transflow::createResultsNodes $tree root $transflows 0
        set node [$tree nodes root end]
        lappend data [$tree itemcget $node -data]
    }
    $tree itemconfigure $node -text "Transitive Flows $title2" -data $data -drawcross auto
}

proc Apol_Analysis_tra::showTransFlow {res data} {
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

proc Apol_Analysis_tra::renderDTA {dir tree dta} {
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

proc Apol_Analysis_tra::showDTA {res data} {
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

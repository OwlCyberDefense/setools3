# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidget


##############################################################
# ::Apol_FSContexts
#
#
##############################################################
namespace eval Apol_FSContexts {
    variable widgets
    variable vals
}

proc Apol_FSContexts::set_Focus_to_Text {} {
    focus $Apol_FSContexts::widgets(results)
}

proc Apol_FSContexts::open {} {
    variable vals

    genfscon_open
    fsuse_open

    # force a flip to the genfscon page
    set vals(context_type) genfscon
}

proc Apol_FSContexts::close {} {
    variable widgets

    initializeVars
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearContextSelector $widgets(genfscon:context)
    Apol_Widget::clearContextSelector $widgets(fsuse:context)
    $widgets(genfscon:fs) configure -values {}
    $widgets(fsuse:type) configure -values {}
    $widgets(fsuse:fs) configure -values {}
}

proc Apol_FSContexts::initializeVars {} {
    variable vals
    array set vals {
        items {}
        context_type genfscon
        genfscon:items {}
        genfscon:fs_enable 0     genfscon:fs {}
        genfscon:path_enable 0   genfscon:path {}

        fsuse:items {}
        fsuse:type_enable 0  fsuse:type {}
        fsuse:fs_enable 0    fsuse:fs {}
    }
}

proc Apol_FSContexts::search { str case_Insensitive regExpr srch_Direction } {
    variable widgets
    ApolTop::textSearch $widgets(results).tb $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_FSContexts::goto_line { line_num } {
    variable widgets
    Apol_Widget::gotoLineSearchResults $widgets(results) $line_num
}

proc Apol_FSContexts::create {nb} {
    variable widgets
    variable vals

    initializeVars

    # Layout frames
    set frame [$nb insert end $ApolTop::fs_contexts_tab -text "FS Contexts"]
    set pw [PanedWindow $frame.pw -side top -weights extra]
    set leftf [$pw add -weight 0]
    set rightf [$pw add -weight 1]
    pack $pw -fill both -expand yes

    # build the left column, where one selects a particular type of
    # context; below it will be a scrolled listbox of keys for that
    # context
    set context_box [TitleFrame $leftf.context_f -text "Context Type"]
    set context_f [$context_box getframe]
    radiobutton $context_f.genfscon -text "genfscon" -value genfscon \
        -variable Apol_FSContexts::vals(context_type)
    radiobutton $context_f.fsuse -text "fs_use" -value fsuse \
        -variable Apol_FSContexts::vals(context_type)
    trace add variable Apol_FSContexts::vals(context_type) write \
        {Apol_FSContexts::contextTypeChanged}
    pack $context_f.genfscon $context_f.fsuse \
        -anchor w -expand 0 -padx 4 -pady 5
    pack $context_box -expand 0 -fill x

    set widgets(items_tf) [TitleFrame $leftf.items_f -text "GenFS Contexts"]
    set widgets(items) [Apol_Widget::makeScrolledListbox [$widgets(items_tf) getframe].items \
                            -height 20 -width 20 -listvar Apol_FSContexts::vals(items)]
    Apol_Widget::setListboxCallbacks $widgets(items) \
        {{"Show Context Info" {Apol_FSContexts::popupContextInfo}}}
    pack $widgets(items) -expand 1 -fill both
    pack $widgets(items_tf) -expand 1 -fill both

    # build the search options
    set optsbox [TitleFrame $rightf.optsbox -text "Search Options"]
    pack $optsbox -side top -expand 0 -fill both -padx 2
    set widgets(options_pm) [PagesManager [$optsbox getframe].pm]

    genfscon_create [$widgets(options_pm) add genfscon]
    fsuse_create [$widgets(options_pm) add fsuse]

    $widgets(options_pm) compute_size
    pack $widgets(options_pm) -expand 1 -fill both -side left
    $widgets(options_pm) raise genfscon

    # add okay button to the top-right corner
    set ok [button [$optsbox getframe].ok -text "OK" -width 6 \
                -command Apol_FSContexts::runSearch]
    pack $ok -side right -pady 5 -padx 5 -anchor ne

    # build the results box
    set resultsbox [TitleFrame $rightf.resultsbox -text "Search Results"]
    pack $resultsbox -expand yes -fill both -padx 2
    set widgets(results) [Apol_Widget::makeSearchResults [$resultsbox getframe].results]
    pack $widgets(results) -side top -expand yes -fill both

    return $frame
}

#### private functions below ####

proc Apol_FSContexts::popupContextInfo {value} {
    variable vals
    if {$vals(context_type) == "genfscon"} {
        genfscon_popup $value
    } else {
        fsuse_popup $value
    }
}

proc Apol_FSContexts::contextTypeChanged {name1 name2 op} {
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    if {$vals(context_type) == "genfscon"} {
        genfscon_show
    } else {
        fsuse_show
    }
}

proc Apol_FSContexts::toggleCheckbutton {path name1 name2 op} {
    variable vals
    variable widgets
    if {$vals($name2)} {
        $path configure -state normal
    } else {
        $path configure -state disabled
    }
}

proc Apol_FSContexts::runSearch {} {
    variable vals
    variable widgets

    Apol_Widget::clearSearchResults $widgets(results)
    if {![ApolTop::is_policy_open]} {
        tk_messageBox -icon error -type ok -title "Error" -message "No current policy file is opened!"
        return
    }
    if {$vals(context_type) == "genfscon"} {
        genfscon_runSearch
    } else {
        fsuse_runSearch
    }
}

proc Apol_FSContexts::fscontext_sort {a b} {
    if {[set z [string compare [lindex $a 0] [lindex $b 0]]] != 0} {
        return $z
    }
    if {[set z [string compare [lindex $a 1] [lindex $b 1]]] != 0} {
        return $z
    }
    return 0
}

#### genfscon private functions below ####

proc Apol_FSContexts::genfscon_open {} {
    variable vals
    variable widgets
    set fstypes {}
    foreach genfs [lsort -unique -index 0 [apol_GetGenFSCons {} {} {} 0]] {
        lappend fstypes [lindex $genfs 0]
    }
    set vals(genfscon:items) $fstypes
    $widgets(genfscon:fs) configure -values $fstypes
}

proc Apol_FSContexts::genfscon_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "GenFS Contexts"
    $widgets(options_pm) raise genfscon
    set vals(items) $vals(genfscon:items)
}

proc Apol_FSContexts::genfscon_create {p_f} {
    variable widgets
    variable vals

    set fs [frame $p_f.fs]
    set fs_cb [checkbutton $fs.fs_enable -text "Filesystem" \
                   -variable Apol_FSContexts::vals(genfscon:fs_enable)]
    set widgets(genfscon:fs) [ComboBox $fs.fs -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(genfscon:fs) -autopost 1]
    trace add variable Apol_FSContexts::vals(genfscon:fs_enable) write \
        [list Apol_FSContexts::toggleCheckbutton $widgets(genfscon:fs)]
    pack $fs_cb -side top -anchor w
    pack $widgets(genfscon:fs) -side top -expand 0 -fill x -padx 4

    set p [frame $p_f.p]
    set p_cb [checkbutton $p.p_enable -text "Path" \
                   -variable Apol_FSContexts::vals(genfscon:path_enable)]
    set widgets(genfscon:path) [entry $p.path -bg white -width 24 \
                                    -state disabled \
                                    -textvariable Apol_FSContexts::vals(genfscon:path)]
    trace add variable Apol_FSContexts::vals(genfscon:path_enable) write \
        [list Apol_FSContexts::toggleCheckbutton $widgets(genfscon:path)]
    pack $p_cb -side top -anchor w
    pack $widgets(genfscon:path) -side top -expand 0 -fill x -padx 4

    frame $p_f.c
    set widgets(genfscon:context) [Apol_Widget::makeContextSelector $p_f.c.context "Contexts"]
    pack $widgets(genfscon:context)

    pack $fs $p $p_f.c -side left -anchor n -padx 4 -pady 2
}

proc Apol_FSContexts::genfscon_render {genfscon {compact 0}} {
    foreach {fstype path objclass context} $genfscon {break}
    set context [apol_RenderContext $context]
    if {$objclass != "any"} {
        if {$compact} {
            format "genfscon %s %s -t%s %s" $fstype $path $objclass $context
        } else {
            format "genfscon  %-12s %-24s -t%-4s %s" \
                $fstype $path $objclass $context
        }
    } else {
        if {$compact} {
            format "genfscon %s %s %s" $fstype $path $context
        } else {
            format "genfscon  %-12s %-24s %s" \
                $fstype $path $context
        }
    }
}

proc Apol_FSContexts::genfscon_popup {fstype} {
    set genfscons [apol_GetGenFSCons $fstype]
    set text "genfs filesystem $fstype ([llength $genfscons] context"
    if {[llength $genfscons] != 1} {
        append text s
    }
    append text ")"
    foreach g [lsort -index 1 -dictionary $genfscons] {
        append text "\n\t[genfscon_render $g 1]"
    }
    Apol_Widget::showPopupText "filesystem $fstype" $text
}

proc Apol_FSContexts::genfscon_runSearch {} {
    variable vals
    variable widgets

    set fstype {}
    set path {}
    set context {}
    set range_match 0
    if {$vals(genfscon:fs_enable) && [set fstype $vals(genfscon:fs)] == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No filesystem selected."
        return
    }
    if {$vals(genfscon:path_enable) && [set path $vals(genfscon:path)] == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No path given."
        return
    }
    if {[Apol_Widget::getContextSelectorState $widgets(genfscon:context)]} {
        foreach {context range_match} [Apol_Widget::getContextSelectorValue $widgets(genfscon:context)] {break}
    }
    if {[catch {apol_GetGenFSCons $fstype $path $context $range_match} genfscons]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining genfscons list: $genfscons"
        return
    }
    # now display results
    set results "GENFSCONS:"
    if {[llength $genfscons] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach g [lsort -command fscontext_sort $genfscons] {
            append results "\n[genfscon_render $g]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}


#### fs_use private functions below ####

proc Apol_FSContexts::fsuse_open {} {
    variable vals
    variable widgets
    set fsuses [apol_GetFSUses {} {} {} 0]
    set behavs {}
    foreach fsuse [lsort -unique -index 0 $fsuses] {
        lappend behavs [lindex $fsuse 0]
    }
    $widgets(fsuse:type) configure -values $behavs
    set fstypes {}
    foreach fsuse [lsort -unique -index 1 $fsuses] {
        lappend fstypes [lindex $fsuse 1]
    }
    $widgets(fsuse:fs) configure -values $fstypes
    set vals(fsuse:items) $fstypes
}

proc Apol_FSContexts::fsuse_show {} {
    variable vals
    variable widgets
    $widgets(items_tf) configure -text "fs_use Contexts"
    $widgets(options_pm) raise fsuse
    set vals(items) $vals(fsuse:items)
}

proc Apol_FSContexts::fsuse_create {p_f} {
    variable widgets
    variable vals

    set t [frame $p_f.t]
    set type_cb [checkbutton $t.type_enable -text "Statement type" \
                   -variable Apol_FSContexts::vals(fsuse:type_enable)]
    set widgets(fsuse:type) [ComboBox $t.type -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(fsuse:type) -autopost 1]
    trace add variable Apol_FSContexts::vals(fsuse:type_enable) write \
        [list Apol_FSContexts::toggleCheckbutton $widgets(fsuse:type)]
    pack $type_cb -side top -anchor w
    pack $widgets(fsuse:type) -side top -expand 0 -fill x -padx 4

    set fs [frame $p_f.fs]
    set fs_cb [checkbutton $fs.fs_enable -text "Filesystem" \
                   -variable Apol_FSContexts::vals(fsuse:fs_enable)]
    set widgets(fsuse:fs) [ComboBox $fs.fs -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(fsuse:fs) -autopost 1]
    trace add variable Apol_FSContexts::vals(fsuse:fs_enable) write \
        [list Apol_FSContexts::toggleCheckbutton $widgets(fsuse:fs)]
    pack $fs_cb -side top -anchor w
    pack $widgets(fsuse:fs) -side top -expand 0 -fill x -padx 4

    frame $p_f.c
    set widgets(fsuse:context) [Apol_Widget::makeContextSelector $p_f.c.context "Contexts"]
    pack $widgets(fsuse:context)

    pack $t $fs $p_f.c -side left -anchor n -padx 4 -pady 2
}

proc Apol_FSContexts::fsuse_render {fsuse} {
    foreach {behav fstype context} $fsuse {break}
    if {$behav == "fs_use_psid"} {
        # fs_use_psid has no context, so don't render that part
        format "%-13s %s;" $behav $fstype
    } else {
        format "%-13s %-10s %s;" $behav $fstype [apol_RenderContext $context]
    }
}

proc Apol_FSContexts::fsuse_popup {fs} {
    set fsuses [apol_GetFSUses $fs]
    set text "fs_use $fs ([llength $fsuses] context"
    if {[llength $fsuses] != 1} {
        append text s
    }
    append text ")"
    foreach u [lsort -index 1 -dictionary $fsuses] {
        append text "\n\t[fsuse_render $u]"
    }
    Apol_Widget::showPopupText $fs $text
}

proc Apol_FSContexts::fsuse_runSearch {} {
    variable vals
    variable widgets
    set behavior {}
    set fstype {}
    set context {}
    set range_match 0
    if {$vals(fsuse:type_enable) && [set behavior $vals(fsuse:type)] == {}} {
            tk_messageBox -icon error -type ok -title "Error" -message "No fs_use statement type selected."
            return
    }
    if {$vals(fsuse:fs_enable) && [set fstype $vals(fsuse:fs)] == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No filesystem selected."
        return
    }
    if {[Apol_Widget::getContextSelectorState $widgets(fsuse:context)]} {
        foreach {context range_match} [Apol_Widget::getContextSelectorValue $widgets(fsuse:context)] {break}
    }
    if {[catch {apol_GetFSUses $fstype $behavior $context $range_match} fsuses]} {
        tk_messageBox -icon error -type ok -title "Error" -message "Error obtaining fs_use list: $fsuses"
        return
    }
    # now display results
    set results "FS_USES:"
    if {[llength $fsuses] == 0} {
        append results "\nSearch returned no results."
    } else {
        foreach u [lsort -command fscontext_sort $fsuses] {
            append results "\n[fsuse_render $u]"
        }
    }
    Apol_Widget::appendSearchResultText $widgets(results) $results
}

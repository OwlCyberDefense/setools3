# Copyright (C) 2001-2006 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information 

# TCL/TK GUI for SE Linux policy analysis
# Requires tcl and tk 8.4+, with BWidgets


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
    variable vals
    variable widgets
    Apol_Widget::clearSearchResults $widgets(results)
    Apol_Widget::clearContextSelector $widgets(genfscon:context)
    Apol_Widget::clearContextSelector $widgets(fsuse:context)
    $widgets(genfscon:fs) configure -values {}
    $widgets(fsuse:type) configure -values {}
    $widgets(fsuse:fs) configure -values {}
    array set vals {
        items {}
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

    array set vals {
        context_type genfscon        items {}
    }

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
        -anchor w -expand 0 -padx 5 -pady 5
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
    set fstypes [lsort -unique [apol_GetGenFSConFilesystems]]
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
    array set vals {
        genfscon:items {}
        genfscon:fs_enable 0     genfscon:fs {}
        genfscon:path_enable 0   genfscon:path {}
    }

    frame $p_f.opts -relief sunken -bd 1

    set fs [frame $p_f.opts.fs]
    set fs_cb [checkbutton $fs.fs_enable -text "Filesystem" \
                   -variable Apol_FSContexts::vals(genfscon:fs_enable)]
    set widgets(genfscon:fs) [ComboBox $fs.fs -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(genfscon:fs)]
    bind $widgets(genfscon:fs).e <KeyPress> [list ApolTop::_create_popup $widgets(genfscon:fs) %W %K]
    trace add variable Apol_FSContexts::vals(genfscon:fs_enable) write \
        [list Apol_FSContexts::toggleCheckbutton $widgets(genfscon:fs)]
    pack $fs_cb -side top -anchor w
    pack $widgets(genfscon:fs) -side top -expand 0 -fill x -padx 4

    set p [frame $p_f.opts.p]
    set p_cb [checkbutton $p.p_enable -text "Path" \
                   -variable Apol_FSContexts::vals(genfscon:path_enable)]
    set widgets(genfscon:path) [entry $p.path -bg white -width 24 \
                                    -state disabled \
                                    -textvariable Apol_FSContexts::vals(genfscon:path)]
    trace add variable Apol_FSContexts::vals(genfscon:path_enable) write \
        [list Apol_FSContexts::toggleCheckbutton $widgets(genfscon:path)]
    pack $p_cb -side top -anchor w
    pack $widgets(genfscon:path) -side top -expand 0 -fill x -padx 4

    pack $fs $p -side left -anchor n -padx 4 -pady 4
    
    frame $p_f.c -relief sunken -bd 1
    set widgets(genfscon:context) [Apol_Widget::makeContextSelector $p_f.c.context "Contexts"]
    pack $widgets(genfscon:context)
    pack $p_f.opts $p_f.c -side left -padx 4 -expand 0 -fill y
}

proc Apol_FSContexts::genfscon_render {genfscon {compact 0}} {
    foreach {fstype path filetype context} $genfscon {break}
    set context [apol_RenderContext $context [ApolTop::is_mls_policy]]
    if {$filetype != "any"} {
        if {$compact} {
            format "genfscon %s %s -t%s %s" $fstype $path $filetype $context
        } else {
            format "genfscon  %-12s %-24s -t%-4s %s" \
                $fstype $path $filetype $context
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

    if {$vals(genfscon:fs_enable) && $vals(genfscon:fs) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No filesystem selected."
        return
    }
    if {$vals(genfscon:path_enable) && $vals(genfscon:path) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No path given."
        return
    }
    if {[Apol_Widget::getContextSelectorState $widgets(genfscon:context)]} {
        foreach {vals_context vals_range_match} [Apol_Widget::getContextSelectorValue $widgets(genfscon:context)] {break}
    } else {
        set vals_context {}
    }
    set orig_genfscons [apol_GetGenFSCons]

    # apply filters to list
    set genfscons {}
    foreach g $orig_genfscons {
        foreach {fstype path filetype context} $g {break}
        if {$vals(genfscon:fs_enable) && $fstype != $vals(genfscon:fs)} {
            continue
        }
        if {$vals(genfscon:path_enable) && $path != $vals(genfscon:path)} {
            continue
        }
        if {$vals_context != {} && ![apol_CompareContexts $vals_context $context $vals_range_match]} {
            continue
        }
        lappend genfscons $g
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
    set behavs [lsort [apol_GetFSUseBehaviors]]
    $widgets(fsuse:type) configure -values $behavs
    set fstypes {}
    foreach f [lsort -unique -index 1 [apol_GetFSUses]] {
        lappend fstypes [lindex $f 1]
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
    array set vals {
        fsuse:items {}
        fsuse:type_enable 0  fsuse:type {}
        fsuse:fs_enable 0    fsuse:fs {}
    }

    frame $p_f.opts -relief sunken -bd 1

    set t [frame $p_f.opts.t]
    set type_cb [checkbutton $t.type_enable -text "Statement Type" \
                   -variable Apol_FSContexts::vals(fsuse:type_enable)]
    set widgets(fsuse:type) [ComboBox $t.type -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(fsuse:type)]
    bind $widgets(fsuse:type).e <KeyPress> [list ApolTop::_create_popup $widgets(fsuse:type) %W %K]
    trace add variable Apol_FSContexts::vals(fsuse:type_enable) write \
        [list Apol_FSContexts::toggleCheckbutton $widgets(fsuse:type)]
    pack $type_cb -side top -anchor w
    pack $widgets(fsuse:type) -side top -expand 0 -fill x -padx 4

    set fs [frame $p_f.opts.fs]
    set fs_cb [checkbutton $fs.fs_enable -text "Filesystem" \
                   -variable Apol_FSContexts::vals(fsuse:fs_enable)]
    set widgets(fsuse:fs) [ComboBox $fs.fs -entrybg white -width 12 -state disabled \
                                  -textvariable Apol_FSContexts::vals(fsuse:fs)]
    bind $widgets(fsuse:fs).e <KeyPress> [list ApolTop::_create_popup $widgets(fsuse:fs) %W %K]
    trace add variable Apol_FSContexts::vals(fsuse:fs_enable) write \
        [list Apol_FSContexts::toggleCheckbutton $widgets(fsuse:fs)]
    pack $fs_cb -side top -anchor w
    pack $widgets(fsuse:fs) -side top -expand 0 -fill x -padx 4

    pack $t $fs -side left -anchor n -padx 4 -pady 4
    
    frame $p_f.c -relief sunken -bd 1
    set widgets(fsuse:context) [Apol_Widget::makeContextSelector $p_f.c.context "Contexts"]
    pack $widgets(fsuse:context)
    pack $p_f.opts $p_f.c -side left -padx 4 -expand 0 -fill y
}

proc Apol_FSContexts::fsuse_render {fsuse} {
    foreach {behav fstype context} $fsuse {break}
    if {$behav == "fs_use_psid"} {
        # fs_use_psid has no context, so don't render that part
        format "%-13s %s;" $behav $fstype
    } else {
        format "%-13s %-10s %s;" $behav $fstype [apol_RenderContext $context [ApolTop::is_mls_policy]]
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

    if {$vals(fsuse:type_enable) && $vals(fsuse:type) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No fs_use statement type selected."
        return
    }
    if {$vals(fsuse:fs_enable) && $vals(fsuse:fs) == {}} {
        tk_messageBox -icon error -type ok -title "Error" -message "No filesystem selected."
        return
    }
    if {[Apol_Widget::getContextSelectorState $widgets(fsuse:context)]} {
        foreach {vals_context vals_range_match} [Apol_Widget::getContextSelectorValue $widgets(fsuse:context)] {break}
    } else {
        set vals_context {}
    }
    set orig_fsuses [apol_GetFSUses]

    # apply filters to list
    set fsuses {}
    foreach u $orig_fsuses {
        foreach {behav fstype context} $u {break}
        if {$vals(fsuse:type_enable) && $behav != $vals(fsuse:type)} {
            continue
        }
        if {$vals(fsuse:fs_enable) && $fstype != $vals(fsuse:fs)} {
            continue
        }
        if {$vals_context != {}} {
            # fs_use_psid is special in that it has no context at all
            if {$behav == "fs_use_psid" || \
                ![apol_CompareContexts $vals_context $context $vals_range_match]} {
                continue
            }
        }
        lappend fsuses $u
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

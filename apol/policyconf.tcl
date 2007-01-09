# Copyright (C) 2003-2007 Tresys Technology, LLC
# see file 'COPYING' for use and warranty information

# TCL/TK GUI for SELinux policy analysis
# Requires tcl and tk 8.4+, with BWidget


##############################################################
# ::Apol_PolicyConf
#
# The policy.conf Rules page
###############################################################
namespace eval Apol_PolicyConf {
    variable textbox
}

proc Apol_PolicyConf::set_Focus_to_Text {} {
    focus $Apol_PolicyConf::textbox
    insertionMarkChanged
}

proc Apol_PolicyConf::create {nb} {
    variable textbox

    set frame [$nb insert end $ApolTop::policy_conf_tab -text "Policy Source"]
    set sw [ScrolledWindow $frame.sw -auto none]
    set textbox [text [$sw getframe].text -bg white -wrap none]
    $sw setwidget $textbox
    pack $sw -expand yes -fill both

    bind $textbox <<Insertion>> Apol_PolicyConf::insertionMarkChanged

    rename $textbox ::Apol_PolicyConf::real_text

    # Override the textbox's command to do two things:
    #
    # Deny normal insert and delete commands - but still show the
    # insertion cursor.  (Setting the state to disabled hides
    # insertion cursor.)  Use the 'fakeinsert' and 'fakedelete'
    # commands to make changes.
    #
    # Unfortunately the tk 8.4 text widget does not generate a virtual
    # event whenever the insertion mark moves.  Thus to simulate the
    # behavior, override the mark command to generate the event
    # <<Insertion>> after the mark changes.
    proc ::$textbox {cmd args} {
        switch -- $cmd {
            insert -
            delete { return }
            fakeinsert { set cmd insert }
            fakedelete { set cmd delete }
        }
        set retval [uplevel 1 ::Apol_PolicyConf::real_text $cmd $args]
        if {$cmd == "mark" && [string equal -length 10 $args "set insert"]} {
            event generate $Apol_PolicyConf::textbox <<Insertion>>
        }
        return $retval
    }
}

proc Apol_PolicyConf::insertionMarkChanged {} {
    set lpos [$Apol_PolicyConf::textbox index insert]
    foreach {line col} [split $lpos .] {break}
    set ApolTop::policyConf_lineno "Line $line"
}

proc Apol_PolicyConf::open {policy_path} {
    variable textbox

    $textbox fakedelete 0.0 end
    if {![ApolTop::is_capable "source"]} {
        $textbox fakeinsert end "The currently loaded policy is not a source policy."
    } else {
        set primary_file [lindex $policy_path 1]
        if {[catch {::open $primary_file r} f]} {
            $textbox fakeinsert end "$primary_file does not exist or could not be read by the user."
        } else {
            $textbox fakeinsert end [read $f]
            ::close $f
        }
    }
    $textbox see 0.0
    $textbox mark set insert 1.0
}

proc Apol_PolicyConf::close {} {
    variable textbox
    $textbox fakedelete 0.0 end
}

proc Apol_PolicyConf::search { str case_Insensitive regExpr srch_Direction } {
    variable textbox

    ApolTop::textSearch $textbox $str $case_Insensitive $regExpr $srch_Direction
}

proc Apol_PolicyConf::goto_line { line_num } {
    variable textbox
    ApolTop::goto_line $line_num $textbox
}

# Copyright (C) 2003-2007 Tresys Technology, LLC
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

namespace eval Apol_PolicyConf {
    variable textbox
}

proc Apol_PolicyConf::create {tab_name nb} {
    variable textbox

    set frame [$nb insert end $tab_name -text "Policy Source"]
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
    # Unfortunately the Tk 8.4 text widget does not generate a virtual
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

proc Apol_PolicyConf::open {policy_path} {
    variable textbox

    $textbox fakedelete 0.0 end
    if {![ApolTop::is_capable "source"]} {
        $textbox fakeinsert end "The currently loaded policy is not a source policy."
    } else {
        set primary_file [$policy_path get_primary]
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

proc Apol_PolicyConf::getTextWidget {} {
    variable textbox
    return $textbox
}

proc Apol_PolicyConf::insertionMarkChanged {} {
    set lpos [$Apol_PolicyConf::textbox index insert]
    foreach {line col} [split $lpos .] {break}
    set ApolTop::policyConf_lineno "Line $line"
}

#  Copyright (C) 2003-2007 Tresys Technology, LLC
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


## This module is not a real analysis, but an example that serves as a
## guide to what one must do when creating a module via embedded
## comments.  This file also serves as a template for when new
## analysis modules are created.  To include this module in apol, add
## the file name to apol_SOURCES variable in Makefile.am.
##
## All this module does is display an entry box and echo the contents
## of that box.

## The name space should following the convention of Apol_Analysis_XXX, where
## XXX is a 3-4 letter name for the analysis.
namespace eval Apol_Analysis_foo {
    variable vals
    variable widgets

## Within the namespace command for the module, you must call
## Apol_Analysis::registerAnalysis.  The first argument is the
## namespace name of the module, second is the descriptive display name
## you want to be displayed in the GUI selection box.
    Apol_Analysis::registerAnalysis "Apol_Analysis_foo" "Analysis Template Example"
}

# Called when a policy is opened.
proc Apol_Analysis_foo::open {} {
}

# Called when a policy is closed.  Typically you should reset any
# context or option variables you have.
proc Apol_Analysis_foo::close {} {
    variable vals
    set vals(entry_string) {}
}

# Return a string that describes what the module does.  Do not forget
# that during compilation, blank lines are stripped; thus \n may be
# needed within the text.
proc Apol_Analysis_foo::getInfo {} {
    return "This is an analysis template dialog that simply displays the content
of the entry box.  The purpose of this analysis is to provide a
template for new analyses."
}

# Called when the tool first starts up.  It is given a blank frame to
# which create its search widgets.
proc Apol_Analysis_foo::create {options_frame} {
    variable vals
    set vals(entry_string) {}
    set l [label $options_frame.l -text "Enter Text:"]
    set e [entry $options_frame.e -textvariable Apol_Analysis_foo::vals(entry_string) -width 25 -background white]
    pack $l $e -side left -anchor w
}

# Perform a new analysis.  This function is responsible for obtaining
# a new results tab if the analysis succeeds.  If the analysis was
# successful then return an empty string; otherwise return a string
# describing the error, removing its tab if it had made one.
proc Apol_Analysis_foo::newAnalysis {} {
    variable vals
    if {$vals(entry_string) == "" } {
        return "You must enter text in the entry box."
    }
    set f [Apol_Analysis::createResultTab "Foo" [array get vals]]
    set results_box [text $f.results -bg white]
    pack $results_box -expand yes -fill both
    $results_box insert 0.0 "new analysis: $vals(entry_string)"
    return
}

# Update an existing analysis.  The passed in frame will contain the
# existing results; it is this function's responsibility to clear away
# old data and to store the current search criteria onto the tab.  If
# the analysis was successful then return an empty string; otherwise
# return a string describing the error.  On error Apol_Analysis will
# remove its tab.
proc Apol_Analysis_foo::updateAnalysis {f} {
    variable vals
    if {$vals(entry_string) == "" } {
        return "You must enter text in the entry box."
    }
    Apol_Analysis::setResultTabCriteria [array get vals]
    $f.results delete 0.0 end
    $f.results insert 0.0 "updated analysis: $vals(entry_string)"
    return
}

# Called whenever the user hits the reset criteria button.
proc Apol_Analysis_foo::reset {} {
    variable vals
    set vals(entry_string) {}
}

# Called when the user switches to this tab.  The module should
# restore its search criteria to the values that were stored within
# the tab.
proc Apol_Analysis_foo::switchTab {query_options} {
    variable vals
    array set vals $query_options
}

# Called to save the current criteria to a file channel.
proc Apol_Analysis_foo::saveQuery {channel} {
    variable vals
    foreach {key value} [array get vals] {
        puts $channel "$key $value"
    }
}

# Called to load a query from a file channel.  The module then updates
# its display to match the criteria.
proc Apol_Analysis_foo::loadQuery {channel} {
    variable vals
    while {[gets $channel line] >= 0} {
        set line [string trim $line]
        # Skip empty lines and comments
        if {$line == {} || [string index $line 0] == "#"} {
            continue
        }
        regexp -line -- {^(\S+)( (.+))?} $line -> key --> value
        set vals($key) $value
    }
}

# Highlight a line on a particular result tab.
proc Apol_Analysis_foo::gotoLine {tab line_num} {
    set textbox $tab.results
    # Remove any selection tags.
    $textbox tag remove sel 0.0 end
    $textbox mark set insert ${line_num}.0
    $textbox see ${line_num}.0
    $textbox tag add sel $line_num.0 $line_num.end
    focus $textbox
}

# Search the result tab for some text.
proc Apol_Analysis_foo::search {tab str case_Insensitive regExpr srch_Direction } {
    set textbox $tab.results
    ApolTop::textSearch $textbox $str $case_Insensitive $regExpr $srch_Direction
}

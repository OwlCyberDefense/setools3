1 August 2002
selinux@tresys.com

This file contains instructions on installing our patch of the 
distributed SE Linux policy to include policy management restrictions.
The seuser tool assumes that this patch is applied to the 
system, and that the policy source files are installed as the
patch Makefile assumes.

The file polchanges contains a summary of the changes this patch
does.

NOTE: This patch is only tested against the Jul 03, 2002 and later
release of the policy source directory.


DO I NEED THE PATCH?

First, check to see if you need to apply the patch.  The SE Linux release
starting with the 2.4.19 LSM kernel already has this patch included
and you need not apply it.

This patch was generated against the sourceforge site's August 1 2002 
policy.  So if your policy files were based on downloads earlier, you 
definitely need this patch.  Downloads after 1 August will likely need 
the patch too, as we are not sure when/if the patch will be 
incorporated. Three indicators that might tell you whether you have 
the patched policy sources:

1.	login_contexts defines in ./attribs.te
2.	Makefile has a install-src target
3. 	load_policy.te and checkpolicy.te are in ./domains/programs/

If one or all of these indicators are NOT present, then you probably
need this patch.


INSTALLING THE PATCH

1. Copy the policy-mgt.patch file to your ./selinux/policy source
   directory.

2. cd to the ./selinux/policy directory

3. patch -p1 < policy-mgt.patch

4. make load (this will build and reload the new policy)

5. make install-src  
NOTE: This step is entirely new; it will copy the ./selinux/policy directory 
      to /etc/security/src/policy directory.  From this point forward, you 
      should only re-build the policy from this directory.

6.  At this point you must fix labels on checkpolicy, load_policy, and the
    policy source files.  You can do this by relabeling the entire file system
    (not recommended, but easy to do), or fix the labels manually.  Both 
    options are described below:
    
    a. Manual fix (recommended): Type the following commands
    
    chcon system_u:object_r:checkpolicy_exec_t `which checkpolicy`
    chcon system_u:object_r:load_policy_exec_t `which load_policy`
    chcon -R system_u:object_r:policy_src_t /etc/security/selinux/src
    chcon system_u:object_r:default_context_t /etc/security/default_context
    
    b. Relabel everything: (remember only work from new installed directory)
    
    cd /etc/security/selinux/src/policy
    make relabel
    
    
    


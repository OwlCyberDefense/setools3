/* Copyright (C) 1992,1996-1999,2003,2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/**
 * @file
 *
 * This file looks and acts like /usr/include/ftw.h, with one
 * <em>significant</em> difference.  The standard ftw() and nftw()
 * functions do not permit passing an arbitrary pointer into the
 * callback.  This greatly limits the functions' usefulness on
 * object-oriented systems and in thread-safe libraries.  Thus the
 * header file declares two new functions, new_ftw() and new_nftw(),
 * that act the same as the original, with the addition of an
 * arbitrary void pointer as the last argument.  This void pointer,
 * which may be NULL, is passed into the callback function's last
 * parameter.
 */

/*
 *	X/Open Portability Guide 4.2: ftw.h
 */

#ifndef _NEW_FTW_H
#define	_NEW_FTW_H	1

#include <features.h>

#include <sys/types.h>
#include <sys/stat.h>

__BEGIN_DECLS
/* Values for the FLAG argument to the user function passed to `ftw'
   and 'nftw'.  */
	enum
{
	FTW_F,			       /* Regular file.  */
#define FTW_F	 FTW_F
	FTW_D,			       /* Directory.  */
#define FTW_D	 FTW_D
	FTW_DNR,		       /* Unreadable directory.  */
#define FTW_DNR	 FTW_DNR
	FTW_NS,			       /* Unstatable file.  */
#define FTW_NS	 FTW_NS

#if defined __USE_BSD || defined __USE_XOPEN_EXTENDED

	FTW_SL,			       /* Symbolic link.  */
# define FTW_SL	 FTW_SL
#endif

#ifdef __USE_XOPEN_EXTENDED
/* These flags are only passed from the `nftw' function.  */
	FTW_DP,			       /* Directory, all subdirs have been visited. */
# define FTW_DP	 FTW_DP
	FTW_SLN			       /* Symbolic link naming non-existing file.  */
# define FTW_SLN FTW_SLN
#endif				       /* extended X/Open */
};

#ifdef __USE_XOPEN_EXTENDED
/* Flags for fourth argument of `nftw'.  */
enum
{
	FTW_PHYS = 1,		       /* Perform physical walk, ignore symlinks.  */
# define FTW_PHYS	FTW_PHYS
	FTW_MOUNT = 2,		       /* Report only files on same file system as the
				          argument.  */
# define FTW_MOUNT	FTW_MOUNT
	FTW_CHDIR = 4,		       /* Change to current directory while processing it.  */
# define FTW_CHDIR	FTW_CHDIR
	FTW_DEPTH = 8		       /* Report files in directory before directory itself. */
# define FTW_DEPTH	FTW_DEPTH
# ifdef __USE_GNU
		,
	FTW_ACTIONRETVAL = 16	       /* Assume callback to return FTW_* values instead of
				          zero to continue and non-zero to terminate.  */
#  define FTW_ACTIONRETVAL FTW_ACTIONRETVAL
# endif
};

#ifdef __USE_GNU
/* Return values from callback functions.  */
enum
{
	FTW_CONTINUE = 0,	       /* Continue with next sibling or for FTW_D with the
				          first child.  */
# define FTW_CONTINUE	FTW_CONTINUE
	FTW_STOP = 1,		       /* Return from `ftw' or `nftw' with FTW_STOP as return
				          value.  */
# define FTW_STOP	FTW_STOP
	FTW_SKIP_SUBTREE = 2,	       /* Only meaningful for FTW_D: Don't walk through the
				          subtree, instead just continue with its next
				          sibling. */
# define FTW_SKIP_SUBTREE FTW_SKIP_SUBTREE
	FTW_SKIP_SIBLINGS = 3,	       /* Continue with FTW_DP callback for current directory
				          (if FTW_DEPTH) and then its siblings.  */
# define FTW_SKIP_SIBLINGS FTW_SKIP_SIBLINGS
};
#endif

/* Structure used for fourth argument to callback function for `nftw'.  */
struct FTW
{
	int base;
	int level;
};
#endif				       /* extended X/Open */

/* Convenient types for callback functions.  */
typedef int (*__new_ftw_func_t) (__const char *__filename, __const struct stat * __status, int __flag, void *__data);
#ifdef __USE_LARGEFILE64
typedef int (*__new_ftw64_func_t) (__const char *__filename, __const struct stat64 * __status, int __flag, void *__data);
#endif
#ifdef __USE_XOPEN_EXTENDED
typedef int (*__new_nftw_func_t) (__const char *__filename,
				  __const struct stat * __status, int __flag, struct FTW * __info, void *__data);
# ifdef __USE_LARGEFILE64
typedef int (*__new_nftw64_func_t) (__const char *__filename,
				    __const struct stat64 * __status, int __flag, struct FTW * __info, void *__data);
# endif
#endif

/* Call a function on every element in a directory tree.

   This function is a possible cancellation point and therefore not
   marked with __THROW.  */
#ifndef __USE_FILE_OFFSET64
extern int new_ftw(__const char *__dir, __new_ftw_func_t __func, int __descriptors, void *__data) __nonnull((1, 2));
#else
# ifdef __REDIRECT
extern int __REDIRECT(new_ftw, (__const char *__dir, __new_ftw_func_t __func,
				int __descriptors, void *__data), new_ftw64) __nonnull((1, 2));
# else
#  define new_ftw new_ftw64
# endif
#endif
#ifdef __USE_LARGEFILE64
extern int new_ftw64(__const char *__dir, __new_ftw64_func_t __func, int __descriptors, void *__data) __nonnull((1, 2));
#endif

#ifdef __USE_XOPEN_EXTENDED
/* Call a function on every element in a directory tree.  FLAG allows
   to specify the behaviour more detailed.

   This function is a possible cancellation point and therefore not
   marked with __THROW.  */
# ifndef __USE_FILE_OFFSET64
extern int new_nftw(__const char *__dir, __new_nftw_func_t __func, int __descriptors, int __flag, void *__data) __nonnull((1, 2));
# else
#  ifdef __REDIRECT
extern int __REDIRECT(new_nftw, (__const char *__dir, __new_nftw_func_t __func,
				 int __descriptors, int __flag, void *__data), new_nftw64) __nonnull((1, 2));
#  else
#   define new_nftw new_nftw64
#  endif
# endif
# ifdef __USE_LARGEFILE64
extern int new_nftw64(__const char *__dir, __new_nftw64_func_t __func,
		      int __descriptors, int __flag, void *__data) __nonnull((1, 2));
# endif
#endif

/* Compile new_nftw() to always have LFS enabled. */
extern int __REDIRECT(new_nftw, (__const char *__dir, __new_nftw_func_t __func,
				 int __descriptors, int __flag, void *__data), new_nftw64) __nonnull((1, 2));

__END_DECLS
#endif				       /* ftw.h */

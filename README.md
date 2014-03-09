[![Monit](http://mmonit.com/monit/_Media/logo2x.png)](http://mmonit.com/monit) 
 

#[Monit](http://mmonit.com/monit) is a free open source utility for managing and monitoring, processes, programs, files, directories and filesystems on a UNIX system. Monit conducts automatic maintenance and repair and can execute meaningful causal actions in error situations.#

---

SYSTEM REQUIREMENTS
===================

__Memory and Disk space__. A minimum of 1 megabytes RAM are required and around 500KB of free disk space. You may need more RAM depending on how many services Monit should monitor. 
  
__ANSI-C Compiler and Build System__. You will need an ANSI-C99 compiler installed to build Monit. The GNU C compiler (GCC) from the Free Software Foundation (FSF) is recommended. In addition, your PATH must contain basic build tools such as make.


INSTALLATION
============

Monit utilize the GNU auto-tools and provided the requirements above are
satisfied, building Monit is conducted via the standard;  

> ./configure  
> make  
> make install  

This will install Monit and the Monit man-file in /usr/local/bin and /usr/local/man/man1 respectively. If you want another location than
/usr/local, run configure with the *--prefix* options and specify the install directory.

Use ./configure --help for build and install options. By default, Monit is built with SSL, PAM and large file support. You can change this
with the *--without-<xxx>* options to ./configure. For instance, *--without-ssl*, *--without-pam* or *--without-largefiles*.


QUICK START
===========

After you have built Monit you can simply start the monit program from the build directory to test it. Monit will use the `monitrc` control file
located in this directory for it's configuration. The file is setup to start Monit's http server so you have something interesting to look at;
After you have started monit, point your browser to `http://127.0.0.1:2812/` and log in with the username `admin` and password `monit`.

Once started, monit will run as a background process. To stop monit, use `monit quit`. To run monit in the foreground and in diagnostic mode,
start monit with the -Iv options. In diagnostic mode, monit will print debug information to the console. Use `ctrl+c` to stop monit in
diagnostic mode. To see all options for the program, use `monit -h`.

Copy `monitrc` in the build directory to *$HOME/.monitrc* or if you plan to run Monit as root, to */etc/monitc*. Use this file as a starting
point to write your own configuration file for Monit.


DOCUMENTATION
=============

Please use `man monit` for an in-depth documentation of the program. More documentation can be found at [Monit's web-site](http://mmonit.com/monit/documentation/ "Documentation")


MAILING LIST
============

You can subscribe to [Monitʼs mailing list](https://lists.nongnu.org/mailman/listinfo/monit-announce) to be the first to hear about new releases and important information about Monit. 


CONTRIBUTING
============
 
You are welcome to contribute to this project. Join our [developer mailing
list](https://lists.nongnu.org/mailman/listinfo/monit-dev) and ask first if a new feature is wanted before working on a patch,
otherwise you risk spending a lot of time working on something that the project's developers might not want to merge into the project.
Good pull requests, patches, improvements and new features are helpful and appreciated.

To create a pull request:

* Fork the Monit project
* Create a new topic branch (off the master branch) to contain your feature, change, or fix
* Commit your changes in logical chunks and when done push your changes up to your fork and open a pull request (PR) with a clear title and description against the Monit master branch

In order for the team to accept your change, you must complete the [Tildeslash Contributor Agreement](http://tildeslash.com/cla/)


REPORTING A BUG
===============

If you believe you have found a bug, please use the [issue tracker](https://bitbucket.org/tildeslash/monit/issues) to report the problem.
Remember to include the necessary information that will enable us to understand and reproduce this problem. 

If you have found a security vulnerabilities we appreciate if you will send this information to [cve@tildeslash.com](mailto:cve@tildeslash.com).


ACKNOWLEDGMENTS
===============

Thanks to the [Free Software Foundation](http://www.fsf.org) for hosting the mailing list and to [Atlassian](https://www.atlassian.com) for hosting the code repository.

The design of libmonit was inspired by principles put forth by *David R. Hanson* in his excellent book ["C Interfaces and
Implementations"](http://www.cs.princeton.edu/software/cii/ "CII"). 


CONTACT INFORMATION
===================

Monit is a product of [Tildeslash Ltd.](http://tildeslash.com/) a company registered in Norway and in United Kingdom. For further information about this Software, please visit [http://mmonit.com/contact/](http://mmonit.com/contact/)

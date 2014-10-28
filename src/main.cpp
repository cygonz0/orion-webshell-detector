//orion-webshell-detector by hjerold & gaber52
//File: main.cpp

#include "header.h"

vector<string> phpComments;
vector<string> aspComments;
vector<string> jspComments;

int main(int argc, char *argv[]) {
	
	//populating information of dangerous functions
	// catergory 1
	phpComments.push_back("base64_decode");
	phpComments.push_back("This function decodes a base64 encoded data. Webshells scripts and dangerous functions \n"
						  "may be pre-encoded and this function may pose a security threat.");
	phpComments.push_back("exec");
	phpComments.push_back("This function executes the given command. When allowing user-supplied data to be passed \n"
						  "to this function, use escapeshellarg() or escapeshellcmd() to ensure that users cannot \n"
						  "trick the system into executing arbitrary commands.");
	phpComments.push_back("passthru");
	phpComments.push_back("This function executes the given command. When allowing user-supplied data to be passed \n"
						  "to this function, use escapeshellarg() or escapeshellcmd() to ensure that users cannot \n"
						  "trick the system into executing arbitrary commands.");
	phpComments.push_back("system");
	phpComments.push_back("This function executes an external program and display the output. When allowing user \n"
						  "supplied data to be passed to this function, use escapeshellarg() or escapeshellcmd() \n"
						  "to ensure that users cannot trick the system into executing arbitrary commands.");
	phpComments.push_back("shell_exec");
	phpComments.push_back("This function executes command via shell and return the complete output as a string. \n"
						  "It is advised to check that user input supplied to the function is sanitized.");
	phpComments.push_back("popen");
	phpComments.push_back("This function opens a process file pointer. With safe mode enabled, the command string \n"
						  "is escaped with escapeshellcmd().");
	phpComments.push_back("proc_open");
	phpComments.push_back("This function executes a command and open file pointers for input / output.");
	phpComments.push_back("pcntl_exec");
	phpComments.push_back("This function executes a specified program in current process space. It is advised to \n"
						  "check that user input supplied to the function is sanitized.");
	// catergory 2
	phpComments.push_back("eval");
	phpComments.push_back("This function evaluates a string as PHP code. Caution: the eval() language construct is \n"
						  "very dangerous because it allows execution of arbitrary PHP code. Its use thus is \n"
						  "discouraged. If you have carefully verified that there is no other option than to use \n"
						  "this construct, pay special attention not to pass any user provided data into it without \n"
						  "properly validating it beforehand.");
	phpComments.push_back("assert");
	phpComments.push_back("This function checks if assertion is false.");
	phpComments.push_back("create_function");
	phpComments.push_back("This function creates an anonymous (lambda-style) function.");
	phpComments.push_back("include");
	phpComments.push_back("The include statement includes and evaluates the specified file.");
	phpComments.push_back("include_once");
	phpComments.push_back("The include_once statement includes and evaluates the specified file once.");
	phpComments.push_back("require");
	phpComments.push_back("The require statement includes and evaluates the specified file.");
	phpComments.push_back("require_once");
	phpComments.push_back("The require_once statement includes and evaluates the specified file.");
	phpComments.push_back("ReflectionFunction");
	phpComments.push_back("The ReflectionFunction class reports information about a function.");
	// catergory 3
	phpComments.push_back("ob_start");
	phpComments.push_back("This function turns output buffering on. While output buffering is active no output is \n"
						  "sent from the script, instead the output is stored in an internal buffer.");
	phpComments.push_back("array_diff_uassoc");
	phpComments.push_back("This function computes the difference of arrays with additional index check which is \n"
						  "performed by a user supplied callback function.");
	phpComments.push_back("array_diff_ukey");
	phpComments.push_back("This function computes the difference of arrays using a callback function on the keys for \n"
						  "comparison.");
	phpComments.push_back("array_filter");
	phpComments.push_back("This function filters elements of an array using a callback function.");
	phpComments.push_back("array_intersect_uassoc");
	phpComments.push_back("This function computes the intersection of arrays with additional index check, compares \n"
						  "indexes by a callback function.");
	phpComments.push_back("array_intersect_ukey");
	phpComments.push_back("This function computes the intersection of arrays using a callback function on the keys \n"
						  "for comparison.");
	phpComments.push_back("array_map");
	phpComments.push_back("This function applies the callback to the elements of the given arrays.");
	phpComments.push_back("array_reduce");
	phpComments.push_back("This function iteratively reduce the array to a single value using a callback function.");
	phpComments.push_back("array_udiff_assoc");
	phpComments.push_back("This function computes the difference of arrays with additional index check, compares data \n"
						  "by a callback function.");
	phpComments.push_back("array_udiff_uassoc");
	phpComments.push_back("This function computes the difference of arrays with additional index check, compares data \n"
						  "and indexes by a callback function.");
	phpComments.push_back("array_udiff");
	phpComments.push_back("This function computes the difference of arrays by using a callback function for data \n"
						  "comparison.");
	phpComments.push_back("array_uintersect_assoc");
	phpComments.push_back("This function computes the intersection of arrays with additional index check, compares \n"
						  "data by a callback function.");
	phpComments.push_back("array_uintersect_uassoc");
	phpComments.push_back("This function computes the intersection of arrays with additional index check, compares \n"
						  "data and indexes by a callback function.");
	phpComments.push_back("array_uintersect");
	phpComments.push_back("This function computes the intersection of arrays, compares data by a callback function.");
	phpComments.push_back("array_walk_recursive");
	phpComments.push_back("This function applies a user function recursively to every member of an array.");
	phpComments.push_back("array_walk");
	phpComments.push_back("This function applies a user function to every member of an array.");
	phpComments.push_back("assert_options");
	phpComments.push_back("This function sets / gets the various assert flags.");
	phpComments.push_back("uasort");
	phpComments.push_back("This function sorts an array with a user-defined comparison function and maintain index \n"
						  "association.");
	phpComments.push_back("uksort");
	phpComments.push_back("This function sorts an array by keys using a user-defined comparison function.");
	phpComments.push_back("usort");
	phpComments.push_back("This function sorts an array by values using a user-defined comparison function.");
	phpComments.push_back("preg_replace_callback");
	phpComments.push_back("This function performs a regular expression search and replace using a callback.");
	phpComments.push_back("spl_autoload_register");
	phpComments.push_back("This function registers a given function as __autoload() implementation.");
	phpComments.push_back("iterator_apply");
	phpComments.push_back("This function calls a function for every element in an iterator.");
	phpComments.push_back("call_user_func");
	phpComments.push_back("This function calls the callback given by the first paramenter.");
	phpComments.push_back("call_user_func_array");
	phpComments.push_back("this function calls a callback with an array as parameters.");
	phpComments.push_back("register_shutdown_function");
	phpComments.push_back("This function registers a function for execution on shutdown.");
	phpComments.push_back("register_tick_function");
	phpComments.push_back("This function registers a function for execution on each tick.");
	phpComments.push_back("set_error_handler");
	phpComments.push_back("This function sets a user-defined error handler function.");
	phpComments.push_back("set_exception_handler");
	phpComments.push_back("This function sets a user-defined exeption handler function.");
	phpComments.push_back("session_set_save_handler");
	phpComments.push_back("This function sets user-level session storage functions.");
	phpComments.push_back("sqlite_create_aggregate");
	phpComments.push_back("This function registers an aggregate UDP for use in SQL statements.");
	phpComments.push_back("sqlite_create_function");
	phpComments.push_back("This function registers a regular user defined function for use in SQL statements.");
	// catergory 4
	phpComments.push_back("phpinfo");
	phpComments.push_back("This function outputs information of the current server's PHP configuration. This \n"
						  "function is reveals server's configurations and may pose a security threat as sensitive \n"
						  "information may be disclosed and used to exploit. This function is classified as \n"
						  "information disclosure and its use is discouraged");
	phpComments.push_back("posix_mkfifo");
	phpComments.push_back("This function create a special FIFO file which exists in the file system and acts \n"
						  "as a bidirectional communication endpoint for processes. This function is classified \n"
						  "as information disclosure and its use is discouraged");
	phpComments.push_back("posix_getlogin");
	phpComments.push_back("This function returns the login name of the user owning the current process. If used \n"
						  "inappropriately, the user can obtain the username and attempt a brute-force attack. \n"
						  "This function is classified as information disclosure and its used is discouraged");
	phpComments.push_back("posix_ttyname");
	phpComments.push_back("This function returns a string for the absolute path to the current terminal device that \n"
						  "is open on the file descriptor, fd. This function is classified as information disclosure \n"
						  "and its use is discouraged.");
	phpComments.push_back("getenv");
	phpComments.push_back("This function gets the value of an environment variable. This function is classified as \n"
						  "information disclosure and its used is discouraged");
	phpComments.push_back("get_current_user");
	phpComments.push_back("This function returns the name of the owner of the current PHP script. This function is \n"
						  "classified as information disclosure and its used is discouraged");
	phpComments.push_back("proc_get_status");
	phpComments.push_back("This function fetches data about a process opened using proc_open(). This function is \n"
						  "classified as information disclosure and its used is discouraged");
	phpComments.push_back("get_cfg_var");
	phpComments.push_back("This function gets the value of a PHP configuration option. This function is classified \n"
						  "as information disclosure and its used is discouraged");
	phpComments.push_back("disk_free_space");
	phpComments.push_back("This function, given a string containing a directory, will return the number of bytes \n"
						  "available on the corresponding filesystem or disk partition. This function is classified \n"
						  "as information disclosure and its used is discouraged");
	phpComments.push_back("disk_total_space");
	phpComments.push_back("This function, given a string containing a directory, will return the number of bytes \n"
						  "available on the corresponding filesystem or disk partition. This function is classified \n"
						  "as information disclosure and its used is discouraged");
	phpComments.push_back("diskfreespace");
	phpComments.push_back("This function, given a string containing a directory, will return the number of bytes \n"
						  "available on the corresponding filesystem or disk partition. This function is classified \n"
						  "as information disclosure and its used is discouraged");
	phpComments.push_back("getcwd");
	phpComments.push_back("This function returns the current working directory. This function is classified as \n"
						  "information disclosure and its used is discouraged");
	phpComments.push_back("getlastmod");
	phpComments.push_back("This function gets the last modification date of the current page. This function is \n"
						  "classified as information disclosure and its used is discouraged");
	phpComments.push_back("getmygid");
	phpComments.push_back("This function gets the group ID of the current script. This function is classified \n"
						  "as information disclosure and its used is discouraged");
	phpComments.push_back("getmyinode");
	phpComments.push_back("This function gets the inode of the current script. This function is classified as \n"
						  "information disclosure and its used is discouraged");
	phpComments.push_back("getmypid");
	phpComments.push_back("This function gets the current PHP process ID. This function is classified as information \n"
						  "disclosure and its used is discouraged");
	phpComments.push_back("getmyuid");
	phpComments.push_back("This function gets the user id of the current script. This function is classified as \n"
						  "information disclosure and its used is discouraged");
	// catergory 5
	phpComments.push_back("extract");
	phpComments.push_back("This function imports variables from an array into the current symbol state. Warning: \n"
						  "Do not use extract() on untrusted data, like user input ($_GET, $_FILES, etc). If you do, \n"
						  "for example if you want to run old code that relies on register_globals temporarily, make \n"
						  "sure that you use one of the non-overwriting extract_type values such as EXTR_SKIP and be \n"
						  "aware that you should extract in the same order that's defined in variables_order within \n"
						  "php.ini.");
	phpComments.push_back("parse_str");
	phpComments.push_back("This function parses a string as if it were the query string passed via a URL and sets \n"
						  "variables in the current scope");
	phpComments.push_back("putenv");
	phpComments.push_back("This function sets the values of an environment variable.");
	phpComments.push_back("ini_set");
	phpComments.push_back("This function sets the value of a given configuration option. The configuration option \n"
						  "will keep this new value during the script's execution, and will be restored at the \n"
						  "script's ending.");
	phpComments.push_back("mail");
	phpComments.push_back("This function sends an email. It may be exploited for spam if user input to this function \n"
						  "is not sanitized.");
	phpComments.push_back("header");
	phpComments.push_back("This function is used to send a raw HTTP header.");
	phpComments.push_back("proc_nice");
	phpComments.push_back("This function changes the priority of the current process by the amount specified in \n"
						  "increment. A posive increment will lower the priority of the current process, whereas a \n"
						  "negative increment will raise the priority.");
	phpComments.push_back("proc_terminate");
	phpComments.push_back("This function signals a process that it should terminate. Dangerous if user input that is \n"
						  "not sanitized is allowed as crucial processes can be terminated by a user.");
	phpComments.push_back("proc_close");
	phpComments.push_back("This function closes a process opened by proc_open() and reutrns the exit code of that \n"
						  "process");
	phpComments.push_back("pfsockopen");
	phpComments.push_back("This function opens a persistent internet or Unix domain socket connection.");
	phpComments.push_back("fsockopen");
	phpComments.push_back("This function opens internet or unix domain socket connection.");
	phpComments.push_back("apache_child_terminate");
	phpComments.push_back("This function will register the apache process executing the current PHP request for \n"
						  "termination once execution of the PHP code is completed. It may be used to terminate a \n"
						  "process after a script with high memory consumption has been run as memory will usually \n"
						  "only be freed internally but not given back to the operating system.");
	phpComments.push_back("posix_kill");
	phpComments.push_back("This function sends the kill signal sig to the process with the process identifier pid");
	phpComments.push_back("posix_mkfifo");
	phpComments.push_back("This function creates a special FIFO file which exists in the file system and acts as a \n"
						  "bidirectional communication endpoint for processes.");
	phpComments.push_back("posix_setpgid");
	phpComments.push_back("This function lets the process pid join the process group gpid.");
	phpComments.push_back("posix_setsid");
	phpComments.push_back("This function maes the current process a session leader.");
	phpComments.push_back("posix_setuid");
	phpComments.push_back("This function sets the real user ID of the current process. This is a privileged function \n"
						  "that needs appropriate privileges (usually root) on the system to be able to perform this \n"
						  "function.");
	// catergory 6
	phpComments.push_back("fopen");
	phpComments.push_back("This function opens the file specified.\n"
							"Allowing user input may allow users to open files and perform modifications without\n"
							"knowledge of the server admin");
	phpComments.push_back("bzopen");
	phpComments.push_back("This function opens the bzip2 file specified.\n"
							"Allowing user input may allow users to open files and perform modifications without\n"
							"knowledge of the server admin");
	phpComments.push_back("gzopen");
	phpComments.push_back("This function opens the gz file specified.\n"
							"Allowing user input may allow users to open files and perform modifications without\n"
							"knowledge of the server admin");
	phpComments.push_back("SplFileObject->__construct");
	phpComments.push_back("This function creates a file object with the specified file name.\n"
							"Allowing user input may allow users to create new file objects withou server admin knowledge");
	phpComments.push_back("chgrp");
	phpComments.push_back("This function changes the group of the file specified.\n"
							"Allowing user input may allow users to group of the files on the server without admin knowledge,\n"
							"potentially changing to a group with higher permissions");
	phpComments.push_back("chmod");
	phpComments.push_back("This function changes the mode of the file specified.\n"
							"Allowing user input may allow users to change modes of the files on the server without admin knowledge,\n"
							"potentially allowing further unauthorised modification of the server files.");
	phpComments.push_back("chown");
	phpComments.push_back("This function changes the ownership of the file specified.\n"
							"Allowing user input may allow users to change owners of files on the server without admin knowledge,\n"
							"potentially hindering server operations");
	phpComments.push_back("copy");
	phpComments.push_back("This function copies the file specified to a target location.\n"
							"Allowing user input may allow users to copy files on the server to another location.\n"
							"Possibly taking up memory of the server, or to use as a stepping stone for further attacks.");
	phpComments.push_back("file_put_contents");
	phpComments.push_back("This function writes a string to the file specified.\n"
							"Allowing user input may allow users to modify files on the server.\n"
							"This could be used to mess up server operations, or even add new code");
	phpComments.push_back("lchgrp");
	phpComments.push_back("This function changes the group ownership of the symbolic link specified.\n"
							"Allowing user input may allow users to change owners of links on the server without admin knowledge,\n"
							"potentially hindering server operations");
	phpComments.push_back("lchown");
	phpComments.push_back("This function changes the ownership of the symbolic link specified.\n"
							"Allowing user input may allow users to change owners of links on the server without admin knowledge,\n"
							"potentially hindering server operations");
	phpComments.push_back("link");
	phpComments.push_back("This function creates a hard link to the target specified.\n"
							"Allowing user input may allow users to create links to files on the server without admin knowledge.");
	phpComments.push_back("mkdir");
	phpComments.push_back("This function creates a new directory.\n"
							"Allowing user input may allow users to create directories on the server without admin knowledge,\n"
							"and could be used to hide webshells");
	phpComments.push_back("move_uploaded_file");
	phpComments.push_back("This function moves a uploaded file to a specified location.\n"
							"Allowing user input may allow users to move files on the server to other areas without admin knowledge.");
	phpComments.push_back("rename");
	phpComments.push_back("This function renames the file specified.\n"
							"Allowing user input may allow users to rename files on the server without admin knowledge.");
	phpComments.push_back("rmdir");
	phpComments.push_back("This function removes the directory specified.\n"
							"Allowing user input may allow users to remove directories on the server without admin knowledge.");
	phpComments.push_back("symlink");
	phpComments.push_back("This function creates a symbolic link to the file specified.\n"
							"Allowing user input may allow users to create links to files on the server without admin knowledge.");
	phpComments.push_back("tempnam");
	phpComments.push_back("This function creates a file with a unique name.\n"
							"Allowing user input may allow users to create files on the server without admin knowledge.");
	phpComments.push_back("touch");
	phpComments.push_back("This function sets the access and modification time for the file specified.\n"
							"Allowing user input may allow users modify the times for a file,\n"
							"allowing them to hide the fact of them accessing or modifying certain files.");
	phpComments.push_back("unlink");
	phpComments.push_back("This function deletes the specified file.\n"
							"Allowing user input may allow users to delete files on the server, potentially causing\n"
							"problems for the server operations.");
	phpComments.push_back("ftp_get");
	phpComments.push_back("This function retrieves a file from the FTP server and writes to local file.\n"
							"Allowing user input may allow users access to information to files on the FTP server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("ftp_nb_get");
	phpComments.push_back("This function retrieves a file from the FTP server and writes to local file.\n"
							"Allowing user input may allow users access to information to files on the FTP server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("file_get_contents");
	phpComments.push_back("This function reads the entire file into a string.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("file");
	phpComments.push_back("This function reads the entire file into an array.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("file_exist");
	phpComments.push_back("This function checks if a file exists.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("fileatime");
	phpComments.push_back("This function returns the last access time of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("filectime");
	phpComments.push_back("This function returns the inode change time of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("filegroup");
	phpComments.push_back("This function returns the group of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("fileinode");
	phpComments.push_back("This function returns the file node of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("filemtime");
	phpComments.push_back("This function returns the file modification time of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("fileowner");
	phpComments.push_back("This function returns the owner of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("fileperms");
	phpComments.push_back("This function returns the permissions of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("filesize");
	phpComments.push_back("This function returns the size of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("filetype");
	phpComments.push_back("This function returns the file type of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("glob");
	phpComments.push_back("This function finds the pathnames that match the pattern specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("is_writable");
	phpComments.push_back("This function checks if the file or directory specified is writable or not.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("is_writeable");
	phpComments.push_back("This function checks if the file or directory specified is writable or not.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("linkinfo");
	phpComments.push_back("This function returns information about a link.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("lstat");
	phpComments.push_back("This function returns information about a file or symbolic link.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("parse_ini_file");
	phpComments.push_back("This function parses the ini file specified, and returns the settings in an associative array.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("pathinfo");
	phpComments.push_back("This function returns information about a filepath.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("readfile");
	phpComments.push_back("This function allows users to read a file, and printing it to the standard output.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("readlink");
	phpComments.push_back("This function returns the target of a symbolic link.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("realpath");
	phpComments.push_back("This function returns the canoicalized absolute pathname of the file specified.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("stat");
	phpComments.push_back("This function returns information about a file.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("gzfile");
	phpComments.push_back("This function allows users to read a gz file, by decompressing it and returns the file in an array.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("readgzfile");
	phpComments.push_back("This function allows users to read a gz file, by decompressing it and printing it to the standard output.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("ftp_put");
	phpComments.push_back("This function allows users to store a local file on the FTP server.\n"
							"Allowing user input may allow users to place certain files on the server to the FTP server,\n"
							"making the file downloadable by others");
	phpComments.push_back("ftp_nb_put");
	phpComments.push_back("This function allows users to store a local file on the FTP server.\n"
							"Allowing user input may allow users to place certain files on the server to the FTP server,\n"
							"making the file downloadable by others");
	phpComments.push_back("exif_read_data");
	phpComments.push_back("This function allows users to read the EXIF headers from JPEG or TIFF.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("read_exif_data");
	phpComments.push_back("This function allows users to read the EXIF headers from JPEG or TIFF.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("exif_thumbnail");
	phpComments.push_back("This function allows users to obtain the embedded thumbnail of a TIFF or JPEG image on the server.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("exif_imagetype");
	phpComments.push_back("This function allows users to determine the type of an image on the server.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("hash_file");
	phpComments.push_back("This function allows users to obtain the hash of a file on the server with the specified hash algorithm.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("hash_hmac_file");
	phpComments.push_back("This function allows users to generate the hash of a file on the server using the HMAC method.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("hash_update_file");
	phpComments.push_back("This function allows users to pump data into an active hashing context from a file.\n"
							"Allowing user input would let users pump data of their chooing from a file of their choice.");
	phpComments.push_back("md5_file");
	phpComments.push_back("This function allows users to obtain the MD5 hash of a file on the server.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("sha1_file");
	phpComments.push_back("This function allows users to obtain the SHA1 hash of a file on the server.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("highlight_file");
	phpComments.push_back("This function allows users to retrieve the highlighted version php source code of a file.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("show_source");
	phpComments.push_back("This function allows users to retrieve the highlighted version php source code of a file.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("php_strip_whitespace");
	phpComments.push_back("This function allows users to retrieve the php source code of a file with the comments and spaces removed.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	phpComments.push_back("get_meta_tags");
	phpComments.push_back("This function allows users to parse through a file and retrieve content with the <meta> tags.\n"
							"Allowing user input may allow users access to information to other files on the server, that\n"
							"they would otherwise have no access to.");
	// asp
	aspComments.push_back("File System Object");
	aspComments.push_back("File System ojects allow the read and write operations of the servers files. Allowing user input would\n"
							"let users have access to files on the system that they would otherwise have no access to");
	aspComments.push_back("Process variable");
	aspComments.push_back("Processes allow the execution of system commands on the server. When using user input for the data of\n"
							"the process attributes, would allow users to execute sysem operations on the server");
	aspComments.push_back("Command Object");
	aspComments.push_back("Command objects allow the running of system commands on the server. When allowing user-supplied data\n"
							"to be passed to this function, users will have the ability to run system operations on the server.");
	// jsp
	jspComments.push_back(".loadClass");
	jspComments.push_back("This function loads a Java class specified by the arguments. Allowing user input would\n"
							"let users to load a arbitrary class.");
	jspComments.push_back("new FileInputStream");
	jspComments.push_back("This function creates a reader that can be used to read from a file. Allowing user input would\n"
							"let users access a file on the server that the user would otherwise have no access to.");
	jspComments.push_back("new FileReader");
	jspComments.push_back("This function creates a reader that can be used to read from a file. Allowing user input would\n"
							"let users access a file on the server that the user would otherwise have no access to.");
	jspComments.push_back("new RandomAccessFile");
	jspComments.push_back("This function creates a reader that can be used to read from a file. Allowing user input would\n"
							"let users access a file on the server that the user would otherwise have no access to.");
	jspComments.push_back("System.setProperty");
	jspComments.push_back("This function allows the setting of some system properties. Allowing user input would\n"
							"let users to alter certain properties that might cause some problems to the execution\n"
							"of certain critical programs.");
	jspComments.push_back("System.load");
	jspComments.push_back("The function loads a system library from a file, using a filename as argument\n"
							"When user input is used, may allow users to load a library of his/her choice,\n"
							"or even from a file previous uploaded by the user, allowing access of functions\n"
							"to the user unexpected to the server admin.");
	jspComments.push_back("System.loadLibrary");
	jspComments.push_back("The function loads a system library using the library name as argument.\n"
							"When user input is used, may allow users to load a library of his/her choice,\n" 
							"allowing access of functions to the user unexpected to the server admin");
	jspComments.push_back(".exec");
	jspComments.push_back("This function executes the given system command. When allowing user-supplied data to be passed \n"
						  "to this function, users will have the ability to run system operations on the server.");
	jspComments.push_back("new ProcessBuilder");
	jspComments.push_back("This function constructs a operating system process using the arguments passed to it.\n"
							"When user input is passed to it, allows them to execute system commands on the server");
	jspComments.push_back(".eval");
	jspComments.push_back("This function evaluates a string as Java code. Caution: the .eval language construct is \n"
						  "very dangerous because it allows execution of arbitrary PHP code. Its use thus is \n"
						  "discouraged. If you have carefully verified that there is no other option than to use \n"
						  "this construct, pay special attention not to pass any user provided data into it without \n"
						  "properly validating it beforehand.");

	string dir, option;
	fstream afile;
	string summaryfile;
	char choice;
	int limit, fileno;
	try {
		
		//Codes to run detector by passing info through command line
		#ifdef _WIN32
			
			if (argc != 3)
				throw 1;
			else {
				
				option = argv[1];
				dir = argv[2];
				//remove double quotes from starting directory
				//if it exists
				if ((dir[0] == '"') || (dir[0] == '\'')) {
					dir.erase(0,1);
					dir.erase(dir.size()-1, 1);
				}
				FileReader reader(dir);
				reader.scanDirectory(dir, option, 1);
			}
			
			summaryfile = dir + "\\Summary\\Summary.txt";
		
		// Codes for running the detector by passing info through prompts
		#else
			cout << "Web Shell Detector v1.0" << endl;
			cout << "Please select an option:" << endl;
			cout << "1. Scan a directory recursively for potentially dangerous functions." << endl;
			cout << "2. Scan a directory recursively for web shells based on signatures." << endl;
			cout << "Enter option: ";
			getline(cin, option);
			cout << endl;
			if (option == "1") {
				cout << "Dangerous function scan selected." << endl;
			} 
			else if (option == "2") {
				cout << "Web shell scan selected." << endl;
			}
			else if (option == "3") {
				cout << "Auto Scan selected." << endl;
			}
			else {
				cout << "Invalid option, exiting..." << endl;
				exit(0);
			}
			cout << "Enter directory path: ";
			getline(cin, dir);
			//remove double quotes from starting directory
			//if it exists
			if ((dir[0] == '"') || (dir[0] == '\'')) {
				dir.erase(0,1);
				dir.erase(dir.size()-1, 1);
			}
			FileReader reader(dir);
			reader.scanDirectory(dir, option, 1);
			summaryfile = dir + "/Summary/Summary.txt";
		#endif
		
		sort(ranking.begin(), ranking.end(), comparer);
		afile.open(summaryfile.c_str(), ios::out | ios::app);
		afile << endl;
		for (int i=0; i < ranking.size(); i++) {
			afile << i+1 << ". ";
			afile << "Filename: " << ranking[i].filename << endl;
			afile << "Score: " << ranking[i].score << endl;
			afile << endl;
		}
		afile.close();
		
		#ifdef _WIN32
		#else
			if (ranking.size() > 0) {
				limit = 10;
				cout << "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" << endl;
				cout << "Summary of Dangerous Functions Scan" << endl;
				cout << "========================================================" << endl;
				for (int i=0; i<=ranking.size(); i++) {
					
					if ((i < limit) && (i<ranking.size())) {
						cout << i+1 << "." << endl;
						cout << "Filename: " << ranking[i].filename << endl;
						cout << "Score: " << ranking[i].score << endl;
						cout << endl;
					}
					else {
						cout << endl;
						cout << "(E)xit, (V)iew Log";
						if (limit > 10)
							cout << ", (P)revious";
						if (i <ranking.size()) {
							cout << ", (N)ext";
						}
						cout << endl;
						cout << "Enter choice: ";
						cin >> choice;
						cin.clear();
						cin.ignore(100, '\n');
						
						switch(choice) {
							case 'e':
							case 'E':	exit(0);
										break;
							case 'p':
							case 'P':	cout << "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" << endl;
										cout << "Summary of Dangerous Functions Scan" << endl;
										cout << "========================================================" << endl;
										if ((i%10)==0)
											i = i - 20;
										else
											i = (i-(i%10)) - 10;
										limit = limit - 10;
										break;
							case 'n':
							case 'N':	cout << "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" << endl;
										cout << "Summary of Dangerous Functions Scan" << endl;
										cout << "========================================================" << endl;
										limit = limit + 10;
										break;
							case 'v':
							case 'V':	choice = ' ';
										cout << "Enter file number to view log: ";
										cin >> fileno;
										reader.retrieveLog(ranking[fileno-1].filename);
										cout << "(B)ack, (E)xit" << endl;
										cout << "Enter choice: ";
										cin >> choice;
										cin.clear();
										cin.ignore(100, '\n');
										switch(choice) {
											case 'b':
											case 'B':	cout << "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" << endl;
														cout << "Summary of Dangerous Functions Scan" << endl;
														cout << "========================================================" << endl;
														if ((i%10)==0)
															i = i - 10;
														else
															i = (i-(i%10));
														break;
											case 'e':
											case 'E':	exit(0);
														break;
											default :	cout << "Please select a valid choice" << endl;
										}
										break;
							default:	cout << "Please select a valid choice" << endl;
						}
						i--;
					}
				}
			}
		#endif
	}
	//catching of exceptions
	catch (int n) {
		return 1;
	}
	catch (exception e) {
		return 1;
	}
	
	return 0;
}


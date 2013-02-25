//orion-webshell-detector by hjerold & gaber52
//header file
//Contains File Reader, File Scanner, Results class declarations

//libraries for required methods
#include <iostream>
#include <fstream>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>
#include <algorithm>
#include <sstream>
#include "md5.h"

using namespace std;

struct Summarized {
	string filename;
	int score;
};

bool comparer(Summarized, Summarized);

//vector declarations used for holding information regarding dangerous functions
extern vector<string> phpComments;
extern vector<string> aspComments;
extern vector<string> jspComments;

//vector declarations used for holding summary of scan
extern vector<Summarized> ranking;

//base64 encode and decode declaration
std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(std::string const& s);

//Results class declaration
class Results {
	public:
		//Constructors and Deconstructors
		Results();
		~Results();
		Results(string, string, string);
		
		//Mutator and Accessor functions
		void setName(string);
		void setLog(string);
		string getName();
		int getScore();
		vector<string> getDangerFunctions();
		
		//method used to compute total score
		int calculateScore();
		
		//method used to add detected dangerous functions to the list
		void addDangerFunctions(string, int, int);
		
		//method to print the results
		void printResults();
		
	private:
		//class attributes
		string cfilename, logfile, format;
		int totalscore;
		vector<string> dangerFunctions;
		
		vector<int> functionScore;
		vector<int> line;
};

//File Scanner class declaratioon
class FileScanner {
	
	public:
		//Constructors and Deconstructors
		FileScanner();
		~FileScanner();
		FileScanner(string, string, string);
		
		//Accessor and Mutator functions
		string getCurrentFileName();
		string getLogfile();
		string getShellLog();
		bool getFlag();
		void setCurrentFile(string);
		void setLogfile(string);
		void setShellLog(string);
		
		//method to scan the file for dangerous functions
		void scanCurrentFile(vector<string>, string);
		
		//method to scan the file for webshell signatures
		void webshellScan(vector<string>);
		
	private:
		//class attributes and private methods
		string cfilename;
		string logfile;
		string shellLog;
		bool flag;
		
		//respective scanners for the different web server languages
		int scanPHP(vector<string>);
		void scanASP(vector<string>);
		void scanJSP(vector<string>);
};

//File Reader class declaration
class FileReader {
	
	public:
		//Constructor and Deconstructor
		FileReader();
		~FileReader();
		FileReader(string);
		
		//Accessor and Mutator functions
		string getDir();
		string getFilePath();
		void setDir(string);
		void setFilePath(string);
		
		//method to scan the directory and sub-directories of specified location
		void scanDirectory(string, string, int);
		void removeLog();
		void retrieveLog(string);
		
	private:
		//class attributes
		string startdir;
		string filepath;
		string cDir;
		vector<string> dangerFunction;
		vector<string> aspFunction;
		vector<string> jspFunction;
		vector<string> signatures;
		string logfolder, shellFolder, summaryfolder;
		string format;
};


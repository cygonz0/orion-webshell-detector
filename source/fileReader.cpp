//orion-webshell-detector by hjerold & gaber52
//File Reader Implementation

#include "header.h"

bool comparer (Summarized a, Summarized b) {
	return (a.score > b.score);
}

//Default Constructor and Deconstructor
FileReader::FileReader(){}

FileReader::~FileReader(){}

//User-defined Constructor
FileReader::FileReader(string startdir) {
	ifstream dangerInput, signatureInput;
	string line;
	int type = 1;
	this->startdir = startdir;
	
	//naming log folders
	#ifdef _WIN32
		this->logfolder= this->startdir + "\\logs";
		this->shellFolder = this->startdir + "\\signatureLogs";
		this->summaryfolder = this->startdir + "\\Summary";
		
	#else 
		this->logfolder= this->startdir + "/logs";
		this->shellFolder = this->startdir + "/signatureLogs";
		this->summaryfolder = this->startdir + "/Summary";
	#endif
	
	
	//retrieving danger functions from text file
	dangerInput.open("dangerFunction");
	if(dangerInput) {
		while (getline(dangerInput, line)) {
			if (line == "7")
				type = 2;
			if (line== "11")
				type = 3;
			switch(type) {
				case 1: dangerFunction.push_back(line);
						break;
				case 2: aspFunction.push_back(line);
						break;
				case 3: jspFunction.push_back(line);
				default:;
			}
		}
	}
	else {
		cout << "ERROR OPENING DANGER FUNCTION FILE. EXITING" << endl;
		exit(0);
	}
	dangerInput.close();
	
	//retrieving web shell signatures from text file
	signatureInput.open("md5-signatures-w-names");
	if(signatureInput) {
		while (getline(signatureInput, line)) {
			signatures.push_back(line);
		}
	}
	else {
		cout << "ERROR OPENING SIGNATURE FILE. EXITING" << endl;
		exit(0);
	}
	signatureInput.close();
	
	//creating log folders
	
	#ifdef _WIN32
		_mkdir(logfolder.c_str());
		_mkdir(shellFolder.c_str());
		_mkdir(summaryfolder.c_str());
	#else 
		mkdir(logfolder.c_str(), 0777);
		mkdir(shellFolder.c_str(), 0777);
		mkdir(summaryfolder.c_str(), 0777);
	#endif

}

//accessor and mutator functions
string FileReader::getDir() {
	return startdir;
}

string FileReader::getFilePath() {
	return filepath;
}

void FileReader::setDir(string startdir) {
	this->startdir = startdir;
}

void FileReader::setFilePath(string filepath) {
	this->filepath = filepath;
}

void FileReader::removeLog() {
	DIR *dp;
	struct dirent *dirp;
  	struct stat filestat;
	FileScanner fs;
	size_t found;
	fstream logger;
	int offset;
	char buffer;
	string filename, logfile, shellLog;
	stringstream ss;
	
	dp = opendir(logfolder.c_str());
	
	
	int i=0;
	
	
	
	if (dp == NULL)
    {
    	cout << "Error opening " << logfolder << endl;
    }
	
	while ((dirp = readdir(dp)) != NULL) {
		
		//ignore files named "." and ".."
		if (!strcmp(dirp->d_name, "..") || !strcmp(dirp->d_name, ".")) {
            continue;
        }
		
		//obtain full filepath
		#ifdef _WIN32
			filepath = logfolder + "\\" + dirp->d_name;
		#else 
			filepath = logfolder + "/" + dirp->d_name;
		#endif
		//filepath = dir + "\\" + dirp->d_name;
		
		if (stat(filepath.c_str(), &filestat)) continue;
		
		remove(filepath.c_str());
	}
	closedir(dp);
}	

//scan directory function
void FileReader::scanDirectory(string dir, string option, int counter){
	DIR *dp;
	struct dirent *dirp;
  	struct stat filestat;
	FileScanner fs;
	size_t found;
	fstream logger, afile;
	int offset;
	char buffer;
	string filename, logfile, shellLog, summaryfile;
	stringstream ss;
	bool flag = false;
	string cDir = dir;

	//naming of file containing the log of webshell signature scan
	//as well as removing results from previous scan if it exists
	
	
	#ifdef _WIN32
		shellLog = shellFolder + "\\signatureScanResults.txt";
		summaryfile = summaryfolder + "\\Summary.txt";
	#else 
		shellLog = shellFolder + "/signatureScanResults.txt";
		summaryfile = summaryfolder + "/Summary.txt";
	#endif
	
	//shellLog = shellFolder + "\\signatureScanResults.txt";
	if (option == "1") {
		removeLog();
		afile.open(summaryfile.c_str(), ios::out);
		afile << "Summary of Dangerous Function Scan Results" << endl;
		afile << "================================================" << endl;
		afile.close();
	}
	else if(option == "2")
		remove(shellLog.c_str());
	else if (option == "999") {}
	else  {
		removeLog();
		remove(shellLog.c_str());
		afile.open(summaryfile.c_str(), ios::out);
		afile << "Summary of Dangerous Function Scan Results" << endl;
		afile << "================================================" << endl;
		afile.close();
	}
		
	
	if ((dir[0] == '"') || (dir[0] == '\'')) {
		dir.erase(0,1);
		dir.erase(dir.size()-1, 1);
	}
	
	dp = opendir(dir.c_str());
	
	
	int i=0;
	
	
	
	if (dp == NULL)
    {
    	cout << "Error opening " << dir << endl;
    }
	
	//while not end of directory
	while ((dirp = readdir(dp)) != NULL) {
		
		//ignore files named "." and ".."
		if (!strcmp(dirp->d_name, "..") || !strcmp(dirp->d_name, ".")) {
            continue;
        }
		
		//obtain full filepath
		#ifdef _WIN32
			filepath = dir + "\\" + dirp->d_name;
		#else 
			filepath = dir + "/" + dirp->d_name;
		#endif
		//filepath = dir + "\\" + dirp->d_name;
		
		if (stat(filepath.c_str(), &filestat)) continue;
		
		//if file detected is a directory, increment of directory lvl counter
		//and call a recursive scanDirectory method for the detected directory
		if (S_ISDIR(filestat.st_mode)) {
			if ((filepath != logfolder) && (filepath!= shellFolder) && (filepath!=summaryfolder)) {
				cout << "directory detected" << endl;
				counter++;	  
				scanDirectory(filepath, "999", counter);
			}
		}
		//if file detected is a regular file,
		else if (S_ISREG(filestat.st_mode)) {
			//retrieving filename
			i = filepath.size()-1;
			while (((filepath[i] != '/') && (filepath[i] != '\\')) && (i>=0)) {
				i--;
			}
			filename = filepath.substr(i+1, filepath.size()-1);
			ss << counter;
			//use filename to name its corresponding log file
			#ifdef _WIN32
				logfile = logfolder + "\\" + filename + "-" + ss.str()+ "-" + ".txt";
			#else 
				logfile = logfolder + "/" + filename + "-" + ss.str()+ "-" + ".txt";
			#endif
			ss.str("");
			
			cout << logfile << endl;
			//setting of log files and current filepath
			fs.setLogfile(logfile);
			fs.setShellLog(shellLog);

			cout << filepath << endl;
			cout << "file detected" << endl;
			fs.setCurrentFile(filepath);
			
			//running of different scans depending on options chosen
			//if option = 2, run webshell scan only
			if (option == "2") 	   
				fs.webshellScan(signatures);
			//if option = 1, run dangerFunction scan only
			else if (option == "1") {
				if ((offset = filepath.find(".php", 0)) != string::npos) {
					format = ".php";				
					fs.scanCurrentFile(dangerFunction, format);
					
				}
				else if ((offset = filepath.find(".asp", 0)) != string::npos) {
					format = ".asp";				
					fs.scanCurrentFile(aspFunction, format);					
				}
				else if ((offset = filepath.find(".aspx", 0)) != string::npos) {
					format = ".aspx";	 	 	 	 
					fs.scanCurrentFile(aspFunction, format);
				}
				else if ((offset = filepath.find(".jsp", 0)) != string::npos) {
					format = ".jsp";				
					fs.scanCurrentFile(jspFunction, format);
				}
				else {//if ((offset = filepath.find(".txt", 0)) != string::npos) {
					format = ".php";				
					fs.scanCurrentFile(dangerFunction, format);
				} 
			}
			//by default it runs both scans
			else {
				fs.webshellScan(signatures);
				if ((offset = filepath.find(".php", 0)) != string::npos) {
					format = ".php";				
					fs.scanCurrentFile(dangerFunction, format);
					
				}
				else if ((offset = filepath.find(".asp", 0)) != string::npos) {
					format = ".asp";				
					fs.scanCurrentFile(aspFunction, format);					
				}
				else if ((offset = filepath.find(".aspx", 0)) != string::npos) {
					format = ".aspx";	 	 	 	 
					fs.scanCurrentFile(aspFunction, format);
				}
				else if ((offset = filepath.find(".jsp", 0)) != string::npos) {
					format = ".jsp";				
					fs.scanCurrentFile(jspFunction, format);
				}
				else if ((offset = filepath.find(".txt", 0)) != string::npos) {
					format = ".php";				
					fs.scanCurrentFile(dangerFunction, format);
				} 
			}
		}
	}
	closedir(dp);
	logger.open(shellLog.c_str(), ios::out | ios::app);
	if (fs.getFlag()) {
		cout << "No signature matches found in " << dir << endl;
		logger << "No signature matches found in " << dir << endl;
	}
	logger.close();
}

void FileReader::retrieveLog(string filename) {
	DIR *dp;
	struct dirent *dirp;
  	struct stat filestat;
	FileScanner fs;
	size_t found;
	fstream logger, afile;
	int offset;
	char buffer;
	string logfile, shellLog, summaryfile;
	string line;
	stringstream ss;
	int i;
	
	i = filename.size()-1;
	while (((filename[i] != '/') && (filename[i] != '\\')) && (i>=0)) {
		i--;
	}
	filename = filename.substr(i+1, filename.size()-1);
	
	dp = opendir(logfolder.c_str());
	
	if (dp == NULL)
    {
    	cout << "Error opening " << logfolder << endl;
    }
	
	//while not end of directory
	while ((dirp = readdir(dp)) != NULL) {
		
		//ignore files named "." and ".."
		if (!strcmp(dirp->d_name, "..") || !strcmp(dirp->d_name, ".")) {
            continue;
        }
		
		//obtain full filepath
		#ifdef _WIN32
			filepath = logfolder + "\\" + dirp->d_name;
		#else 
			filepath = logfolder + "/" + dirp->d_name;
		#endif
		//filepath = dir + "\\" + dirp->d_name;
		
		if (stat(filepath.c_str(), &filestat)) continue;
		
		if (filepath.find(filename, 0) != string::npos) {
			afile.open(filepath.c_str(), ios::in);
			while(getline(afile, line)) {
				cout << line << endl;
			}
			afile.close();
			cout << endl;
		}
	}
	closedir(dp);
}


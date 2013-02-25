//orion-webshell-detector by hjerold & gaber52

//Results class implementation

#include "header.h"

vector<Summarized> ranking;

//Default constructor and deconstructor
Results::Results(){}

Results::~Results(){}

//user-defined constructor
Results::Results(string cfilename, string logfile, string format) {
	this->cfilename = cfilename;
	this->logfile = logfile;
	this->format = format;
	totalscore = 0;
}

//accessor and mutator functions
void Results::setName(string cfilename) {
	this->cfilename = cfilename;
}

void Results::setLog(string logfile) {
	this->logfile = logfile;
}

string Results::getName() {
	return cfilename;
}
		
int Results::getScore(){
	return totalscore;
}

vector<string> Results::getDangerFunctions() {
	return dangerFunctions;
}

//function to calculate the total score of all danger functions detected
int Results::calculateScore() {
	totalscore = 0;
	for (int i=0; i<functionScore.size(); i++){
		totalscore += functionScore[i];
	}
	return totalscore;
}

//function used to add a danger function detected to the results list
void Results::addDangerFunctions(string danger, int score, int lineno) {
	dangerFunctions.push_back(danger);
	functionScore.push_back(score);
	line.push_back(lineno);
}

//function to format the results tabulated and display it in a meaningful manner
void Results::printResults() {
	fstream logger;
	stringstream ss;
	Summarized summary;
	bool found = false;
	int k = calculateScore();
	int j = logfile.size()-1;
	while (((logfile[j] != '/') && (logfile[j] != '\\')) && (j>=0)) {
		j--;
	}
	string logfolder = logfile.substr(0, j);
	string logname = logfile.substr(j+1, logfile.size()-1);
	
	while (((logfolder[j] != '/') && (logfolder[j] != '\\')) && (j>=0)) {
		j--;
	}
	string summaryfolder = logfolder.substr(0,j);
	
	ss << totalscore;
	//use filename to name its corresponding log file
	#ifdef _WIN32
		logfile = logfolder + "\\" + ss.str() + "-" + logname;
	#else 
		logfile = logfolder + "/" + ss.str() + "-" + logname;
	#endif
	
	ss.str("");
	cout << logfile << endl;
	
	summary.score = totalscore;
	summary.filename = cfilename;
	ranking.push_back(summary);
		   
	logger.open(logfile.c_str(), ios::out | ios::app);
	
	if (cfilename.find("decoded",0) != string::npos) {
		logger << "Decoded code score: " << totalscore << endl;
	}
	else {
		logger << "Total Danger Score: " << totalscore << endl;
		logger << endl;
		logger << "===============================================" << endl;
		logger << "Filename: " << cfilename << endl;
		logger << "===============================================" << endl;
		logger << endl;
	}
	
	for (int i=0; i<dangerFunctions.size(); i++){
		if (functionScore[i] > -1) {
			
			logger << "Danger Function: " << dangerFunctions[i] << endl;
			logger << "Line " << line[i] << endl;
			logger << "Score awarded: " << functionScore[i] << endl;
				
			
			//display the reasons why the functions are dangerous
			if (format == ".php") {
				for (int j=0; j<phpComments.size(); j++) {
					if (phpComments[j] == dangerFunctions[i]) {
						logger << "Comments: " << phpComments[j+1] << endl;
						logger << endl;
						break;
					}
				}
			}
			else if (format == ".asp") {
				for (int j=0; j<aspComments.size(); j++) {
					if (aspComments[j].find_first_of(dangerFunctions[i], 0) != string::npos ) {
						logger << "Comments: " << aspComments[j+1] << endl;
						logger << endl;
						break;
					}
				}
			}
			else if (format == ".jsp") {
				for (int j=0; j<jspComments.size(); j++) {
					if (jspComments[j] == dangerFunctions[i]) {
						logger << "Comments: " << jspComments[j+1] << endl;
						logger << endl;
						break;
					}
				}
			}
		}
	}
	cout << endl;
	logger << endl;
	logger.close();
}



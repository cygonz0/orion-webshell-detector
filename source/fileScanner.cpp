//orion-webshell-detector by hjerold & gaber52
//File: fileScanner.cpp

#include "header.h"

//default constructor and deconstructor
FileScanner::FileScanner(){}

FileScanner::~FileScanner(){}

//user-defined constructor
FileScanner::FileScanner(string cfilename, string logfile, string shellLog) {
	fstream logger;
	this->cfilename = cfilename;
	this->logfile = logfile;
	this->shellLog = shellLog;
	this->flag = false;
	
}

//accessor and mutator functions
string FileScanner::getCurrentFileName() {
	return cfilename;
}

string FileScanner::getLogfile() {
	return logfile;
}

string FileScanner::getShellLog() {
	return shellLog;
}

bool FileScanner::getFlag() {
	return flag;
}

void FileScanner::setCurrentFile(string cfilename) {
	this->cfilename = cfilename;
}

void FileScanner::setLogfile(string logfile) {
	this->logfile = logfile;
}

void FileScanner::setShellLog(string shellLog) {
	this->shellLog = shellLog;
}

//function that determines the different scans for the different file formats.
void FileScanner::scanCurrentFile(vector<string> signature, string format){
	if (format == ".php")
		scanPHP(signature);
	else if ((format == ".aspx") || (format == ".asp"))
		scanASP(signature);
	else if (format == ".jsp")
		scanJSP(signature);
	else ;
}

//function to scan php files
int FileScanner::scanPHP(vector<string> signature) {
	//declaring of variables
	ifstream fileInput;
	fstream afile;
	int offset, offset1;
	int category, score;
	int previous, startPos;
	int lineno = 0;	   
	int wall = 0;
	int wall1= 0;
	int wall2= 0;
	int i = 0;
	int j=0;
	int k=0;
	bool variableDone = false;
	string line, variable, variable1, functionName;
	string decoded, decodedFilename, cfile, variable2;
	vector<char> stack;
	vector<string> content;	   
	bool scanned = false;
	bool function = false;
	bool found = false;
	char quote;
	//creating the class to hold the results
	Results r(cfilename, logfile, ".php");

	//generating the filename to hold decoded codes in the
	//even that a base64_encode operation is used to hide codes	   
	cfile = cfilename;
	for (int h=cfilename.size()-1; h>=0; h--) {
		if ((cfilename[h] == '.') || (cfilename[h] == '\\') || (cfilename[h] == '/')) {
			decodedFilename = cfilename.substr(0, h);
			decodedFilename = decodedFilename + " decoded.txt";
			break;
		}
	}
	//retrieving the file contents for scanning
	fileInput.open(cfilename.c_str());
	if(fileInput.is_open()) {
		while(getline(fileInput, line)) {
			transform(line.begin(), line.end(), line.begin(), ::tolower);
			content.push_back(line);
			
		}
		fileInput.close();
	}
	else cout << "Unable to open file.";
	
	signature.push_back("7");
	
	//loop that checks each line of file content
	while(lineno < content.size()) {
		i = 0;
		//cout << lineno << endl;
		//loop that scans line for the any dangerous functions used
		while(i<signature.size()) {
			
			wall = 0;
			//each dangerous function is assigned a category
			//depending on the category, each function could be handled differently
			if (signature[i] == "1") {
				category = 1;
				score = 100;
			}
			else if (signature[i] == "2") {
				category = 2;
				score = 90;
			}
			else if (signature[i] == "3") {
				category = 3;
				score = 5;
			}
			else if (signature[i] == "4") {
				category = 4;
				score = 1;
			}
			else if (signature[i] == "5") {
				category = 5;
				score = 4;
			}
			else if (signature[i] == "6") {
				category = 6;
				score = 6;
			}
			else if (signature[i] == "7") {
				category = 7;
			}
			else {
				
				//continuously scans the same line until scan for all dangerous functions are done
				while ((offset = content[lineno].find(signature[i], wall)) != string::npos) {
					startPos = offset;
					offset = offset + signature[i].size();
					wall = offset+1;
					
					//condition that checks for words that may be wrongly detected as a dangerous function
					if (startPos !=0) {
						if ((content[lineno][startPos-1]>=65 && content[lineno][startPos-1]<=90) ||
											(content[lineno][startPos-1]>=97 && content[lineno][startPos-1]<=122) ||
											(content[lineno][startPos-1]>=48 && content[lineno][startPos-1]<=57) ||
											(content[lineno][startPos-1] == '_')) {
							continue;
						}
					}
					if ((content[lineno][offset]>=65 && content[lineno][offset]<=90) ||
											(content[lineno][offset]>=97 && content[lineno][offset]<=122) ||
											(content[lineno][offset]>=48 && content[lineno][offset]<=57) ||
											(content[lineno][offset] == '_')) {
						continue;
					}
					//if the a open bracket is detected
					else if (content[lineno][offset] == '(') {
						stack.push_back(content[lineno][offset]);
						//scan until a close bracket is found
						while (stack.size() != 0) {
							offset++;
							if (offset >= content[lineno].size() ) {
								lineno++;
								offset=0;
								wall = 0;
							}
							
							//if another open bracket is detected, push it into the stack
							//and continue to find a corresponding close bracket
							if (content[lineno][offset] == '(')
								stack.push_back(content[lineno][offset]);
							//if a '$' is detected, check if it is a userinput or variable
							else if (content[lineno][offset] == '$') {
								offset++;
								//if '_' is detected next, userinput confirmed in danger function
								//add the detected function to the results list
								if (content[lineno][offset] == '_') {
									variable = "";
									offset++;
									while ((content[lineno][offset]>=65 && content[lineno][offset]<=90) ||
											(content[lineno][offset]>=97 && content[lineno][offset]<=122) ||
											(content[lineno][offset]>=48 && content[lineno][offset]<=57) ||
											(content[lineno][offset] == '_')) {
										variable.append(1, content[lineno][offset]);
										offset++;
										
									}
									offset--;
									if ((variable == "get") || (variable == "post") ||
										(variable == "request") || (variable == "session") ||
										(variable == "cookie") || (variable == "files"))
										r.addDangerFunctions(signature[i], score, lineno+1);
									
									//r.addDangerFunctions(signature[i], score, lineno+1);
								}
								//if not '_', variable confirmed. Obtain variable
								else {
									variable = "$";
									while ((content[lineno][offset]>=65 && content[lineno][offset]<=90) ||
											(content[lineno][offset]>=97 && content[lineno][offset]<=122) ||
											(content[lineno][offset]>=48 && content[lineno][offset]<=57) ||
											(content[lineno][offset] == '_')) {
										variable.append(1, content[lineno][offset]);
										offset++;
										
									}
									offset--;
									
									
									j=0;
									k=0;
									wall1=0;
									wall2=0;
									previous = -1;
									variableDone = false;
									scanned = false;
									function = false;
										
									//scan the file contents for the variable.
									while (j<content.size() && !scanned) {
										while (((offset1 = content[j].find(variable,wall1)) != string::npos)) {
											wall1 = offset1 + variable.size();
											//if the same variable was scanned again, end search
											if (j==previous) {
												if (offset1 <= wall2) {
													scanned = true;
													break;
												}
												else {
													wall2 = wall1;
												}
											}
											
											if (j == lineno) {
												scanned = true;
												break;
											}
											
											offset1 = offset1 + variable.size();
											variableDone = false;
											function = false;
									
											//scan until the variable is detected
											while (!variableDone) {
												
												//if space is detected, continue
												if (content[j][offset1] == ' ') 
													offset1++;
												
												//if '=' is detected
												else if (content[j][offset1] == '=') {
													
													offset1++;
													//skip if its inside a foreach loop
													if (content[j][offset1] == '>') {
														scanned = true;
														variableDone = true;
													}
													//skip if the operation is == instead of =
													else if (content[j][offset1] == '=') {
														variableDone = true;
													}
													//if quotes is detected, means that variable
													// is assigned a hardcoded value, not user input
													else if ((content[j][offset1] == '\"') 
															|| (content[j][offset1] == '\'') ) {
														//however if function detected is base64_decode
														//retrieve the contents within the quotes
														if (signature[i] == "base64_decode") {
															quote = content[j][offset1];
															variable1 = "";
															if (offset1 < content[j].size())
																offset1++;
															else {
																j++;
																offset1=0;
															}
															while (content[j][offset1] != quote) {
																variable1 = variable1+content[j][offset1];
																if (offset1 < content[j].size())
																	offset1++;
																else {
																	j++;
																	offset1=0;
																}
															}
															//decode the contents retrieved, write it to a temporary file
															//and scan it using the scanCurrentFile function
															decoded = base64_decode(variable1);
															afile.open(decodedFilename.c_str(), ios::out);
															afile << "base64_decode operation in file \"" << cfile << "\"" << endl;
															afile <<  "Line number " << lineno << endl;
															afile << endl;  
															afile << decoded;
															afile.close();
															
															cfilename = decodedFilename;
															score = scanPHP(signature);
															r.addDangerFunctions(signature[i], score, lineno);
															remove(decodedFilename.c_str());
															cfilename = cfile;
										
														}
														
														scanned = true;
														variableDone = true;
														
													}
													//if no match for any of the above symbols, 
													else {
														
														//continue until ';' is detected
														while (content[j][offset1] != ';') {
															if (content[j][offset1] == ' ') 
																offset1++;
															//if '$' is detected, check if it is userinput
															if ((content[j][offset1] == '$')) {
																
																offset1++;
																variableDone = true;
																//if '_' is detected, userinput confirmed
																if (content[j][offset1] == '_') {
																	variable = "";
																	offset1++;
																	while ((content[j][offset1]>=65 && content[j][offset1]<=90) ||
																		(content[j][offset1]>=97 && content[j][offset1]<=122) ||
																		(content[j][offset1]>=48 && content[j][offset1]<=57) ||
																		(content[j][offset1] == '_')) {
																		variable.append(1, content[j][offset1]);
																		offset1++;
																		
																	}
																	offset1--;
																	if ((variable == "get") || (variable == "post") ||
																		(variable == "request") || (variable == "session") ||
																		(variable == "cookie") || (variable == "files")) {
																		r.addDangerFunctions(signature[i], score, lineno);
																		scanned = true;
																	}
																	//r.addDangerFunctions(signature[i], score, lineno);
																	//scanned = true;
															   	   	   	   	   	   	      	  	  	  	  	  	  
																}
																//else, retrieve the variable assigned to the current variable
																else {
																	wall2 = offset1-1;
																	variable1 = "$";
																	while ((content[j][offset1]>=65 && content[j][offset1]<=90) ||
																			(content[j][offset1]>=97 && content[j][offset1]<=122) ||
																			(content[lineno][offset1]>=48 && content[lineno][offset1]<=57) ||
																			(content[j][offset1] == '_')) {
																		variable1.append(1, content[j][offset1]);
																		offset1++;
																	}
																	//scan the new variable to check if it is user input
																	variable = variable1;
																	previous = j;
																	j=0;
																	wall1=0;							
																}
																break;
															}
															//if end of line, continue on next line
															if (offset1 < content[j].size()-1)
																offset1++;
															else {
																j++;
																offset1=0;
															}
														}	 	 	 	 	 	 
													}
												}
												
												//if a ',' or ')' is detected, means variable is
												//being used in a function
												else if ((content[j][offset1] == ',') 
															|| (content[j][offset1] == ')')) {
													//move counter till '(' is detected
													while (!(content[j][offset1] == '(')) {
														offset1--;
														if (offset1 < 0) {
															j--;
															offset1 = content[j].size() - 1;
														}
														//if "=>" is found, means its not a function but
														//a foreach operation
														if (content[j][offset1] == '>') {
															offset1--;
															if (content[j][offset1] == '=') {
																scanned = true;
																variableDone = true;
																break;
															}
														}
													}
													//if '(' reached, obtain function name
													if (!variableDone) {
														functionName = "";
														offset1--;
														while (content[j][offset1] != ' ') {
															functionName = content[j][offset1] + functionName;
															offset1--;
															//if end of line is reached before a space, means its not
															//a user-defined function header
															if (offset1 < 0) {	  
																break;
															}
															function = true;				
														}
														
														//continue to check if there us the "function" keyword
														if (function) {
															variable1 = "";
															offset1--;
															for (int h=0; h<8; h++) {
																variable1 = content[j][offset1] + variable1;
																offset1--;
																if (offset1 < 0) {
																	break;
																}	 	 	 	 
															}
															found = false;
															//if "function" keyword is found, check if signature list already has it
															if (variable1 == "function") {
																for (int h=signature.size()-1; h>=0; h--) {
																	if (signature[h] == functionName){
																		found = true;
																		break;
																	}
																}
																//if not, add it to the list of dangerous functions and results, as well as giving a warning
																if (!found) {
																	signature.push_back(functionName);
																	phpComments.push_back(functionName);
																	phpComments.push_back("This is a user-defined function that contains the use of a dangerous function.\n" 
																							"Please take care in using it.");
																	r.addDangerFunctions(functionName, 2, lineno);
																	scanned = true;
																} 	     	 	 	 	 	 
															}
														}
													}
													//variableDone = true;
												}	 
												
												//if quotes detected, check the contents if it is under base64_decode operation
												else if ((content[j][offset1] == '\"') 
															|| (content[j][offset1] == '\'') ) {
													if (signature[i] == "base64_decode") {
														quote = content[j][offset1];
														variable1 = "";
														if (offset1 < content[j].size())
															offset1++;
														else {
															j++;
															offset1=0;
														}
														while (content[j][offset1] != quote) {
															variable1 = variable1+content[j][offset1];
															if (offset1 < content[j].size())
																offset1++;
															else {
																j++;
																offset1=0;
															}
														}
														decoded = base64_decode(variable1);
														afile.open(decodedFilename.c_str(), ios::out);
														afile << "base64_decode operation in file \"" << cfile << "\"" << endl;
														afile <<  "Line number " << lineno << endl;
														afile << endl;  
														afile << decoded;
														afile.close();
														
														cfilename = decodedFilename;
														score = scanPHP(signature);
														r.addDangerFunctions(signature[i], score, lineno);
														remove(decodedFilename.c_str());
														cfilename = cfile;
									
													}
													
													scanned = true;
													variableDone = true;
													
												}
												//if no match for any of the above, skip
												else {
													
													scanned = true;
													variableDone = true;
												}
													
												//if reached end of line, continue on next line
												if (offset1 >= content[j].size()) {
													j++;
													offset1=0;
												}
											}  	   
										}
										j++;
									}	 	 	 	 	 	 	 	 
								}
							}
							//if closing bracket detected, pop out 1 from stack
							else if (content[lineno][offset] == ')')
								stack.pop_back();
						
							//if quotes detected, do checking if base64_decode operation is detected.
							else if ((content[lineno][offset] == '"') 
										|| (content[lineno][offset] == '\'')) {
								quote = content[lineno][offset];
								if (signature[i] == "base64_decode") {
									
									variable = "";
									if (offset < content[lineno].size())
										offset++;
									else {
										lineno++;
										offset=0;
									}
									while (content[lineno][offset] != quote) {
										variable = variable+content[lineno][offset];
										if (offset < content[lineno].size())
											offset++;
										else {
											lineno++;
											offset=0;
										}
									}
									decoded = base64_decode(variable);
									afile.open(decodedFilename.c_str(), ios::out);
									afile << "base64_decode operation in file \"" << cfile << "\"" << endl;
									afile <<  "Line number " << lineno << endl;
									afile << endl;  
									afile << decoded;
									afile.close();
															
									cfilename = decodedFilename;
									score = scanPHP(signature);
									r.addDangerFunctions(signature[i], score, lineno);
									remove(decodedFilename.c_str());
									cfilename = cfile;
								}
								
								
								
								//continue until end of quote
								else {
									while (content[lineno][offset] != quote) {
										if (offset < content[lineno].size())
											offset++;
										else {
											lineno++;
											offset=0;
										}
									}
								}
							}
							
							else {
							}
						}
					}
				}
			}
			i++;
		}
		lineno++;
	}
	//display results in a meaningful manner
	cout << endl;
	score = r.calculateScore();
	if (cfilename.find("decoded",0) != string::npos) {
		return score;
	}
	else {
		if (score >0)
			r.printResults();
	}
	return -1;
}

//function to scan for webshell signatures
void FileScanner::webshellScan(vector<string> signatures) {
	MD5 md5;
	Results r;
	fstream logger;
	string fileHash;
	char *a = new char[cfilename.size() + 1];
	a[cfilename.size()] = 0;
	memcpy(a, cfilename.c_str(), cfilename.size());
	fileHash = md5.digestFile(a);
	logger.open(shellLog.c_str(), ios::out | ios::app);
	
	//cout << "MD5 of " << cfilename.c_str() << " file is: " << fileHash << endl;
	//logger << "MD5 of " << cfilename.c_str() << " file is: " << fileHash << endl;
	
	for(unsigned int i = 0; i < signatures.size(); i++) {
		if((signatures[i].c_str()) == fileHash) {
			flag = true;
			cout << "MD5 of " << cfilename << " file is: " << fileHash << endl;
			logger << "MD5 of " << cfilename << " file is: " << fileHash << endl;
	
			cout << "WARNING! IDENTICAL WEBSHELL SIGNATURE DETECTED! WEBSHELL NAME: " << signatures[i+1].c_str() << endl;
			logger << "WARNING! IDENTICAL WEBSHELL SIGNATURE DETECTED! WEBSHELL NAME: " << signatures[i+1].c_str() << endl;
			break;
		}
		
	}
	logger.close();
}

//function to scan asp files
void FileScanner::scanASP(vector<string> signature) {
	ifstream fileInput;
	int offset, offset1;
	int lineno = 0;
	int wall = 0;
	int startPos;
	int i=0;
	int k=0;
	int category, score;
	string line, variable, temp;
	string functionName;
	vector<char> stack;
	vector<string> content;
	vector<string> variables;
	vector<string> userInput;
	vector<int> vline;
	vector<string> functionVariable;
	vector<string> variablesUsed;
	vector<int> fline;
	vector<string> commandVariable;
	bool found = false;
	bool assign = false;
	bool function = false;
	Results r(cfilename, logfile, ".asp");

	//retrieving file content, at the same time changing all to lower case
	fileInput.open(cfilename.c_str());
	if(fileInput.is_open()) {
		while(getline(fileInput, line)) {
			transform(line.begin(), line.end(), line.begin(), ::tolower);
			content.push_back(line);
		}
		fileInput.close();
	}
	else cout << "Unable to open file.";
	
	signature.push_back("11");
	//loop to scan each line
	while(lineno < content.size()) {
		i = 0;
		wall=0;
		if (function) {
			variablesUsed = functionVariable;
		}
		else
			variablesUsed = userInput;
		//loop to scan the line for any user input used.
		while(i<variablesUsed.size()) {
			while ((offset = content[lineno].find(variablesUsed[i], wall)) != string::npos) {
				startPos = offset;
				wall = offset+1;
				assign = true;
				//1st check to determine if the user input was assigned to another variable
				while (content[lineno][offset] != '=') {
					offset--;
					if ((offset<0) || (content[lineno][offset] == ',')
						|| (content[lineno][offset] == '(')) {
						assign = false;
						break;
					}
				}
				
				if (assign) {
					offset--;
					if (content[lineno][offset] == ' ')
						offset--;
									
					variable = "";
					//obtained variable it was assigned to
					while ((content[lineno][offset] != ' ') 
							&& (offset >=0)) {
										
						variable = content[lineno][offset] + variable;
						offset--;
						//2nd check to determine if the user input was assigned to another variable
						if (content[lineno][offset] == '.') {
							assign = false;
							break;
						}
										
					}
					//once variable is obtained, check if it is already recorded in the user input list	   
					if (assign) {
						found = false;
						if (variables.size() !=0) {
							for (int j=0; j<variablesUsed.size(); j++) {
								if (variablesUsed[j] == variable) {
									found = true;
									break;
								}
							}
							//if not, add it to the list
							if (!found) {
								if (function) {
									functionVariable.push_back(variable);
									variablesUsed.push_back(variable);
									fline.push_back(lineno);
								}
								else {
									variables.push_back(variable);
									vline.push_back(lineno);
									userInput.push_back(variable);
									variablesUsed.push_back(variable);
								}
								
							}
						}
						else {
							if (function) {
								functionVariable.push_back(variable);
								variablesUsed.push_back(variable);
								fline.push_back(lineno);
							}
							else {
								variables.push_back(variable);
								vline.push_back(lineno);
								userInput.push_back(variable);
								variablesUsed.push_back(variable);
							}
						}
					}
				}
			}
			i++;
		}
		i=0;
		wall = 0;
		//loop to scan line for dangerous functions
		while(i<signature.size()) {
			//seperating functions in to categories
			//functions may be handled differently depending on its category
			if (signature[i] == "7") {
				category = 7;
			}
			else if (signature[i] == "8") {
				category = 8;
			}
			else if (signature[i] == "9") {
				category = 9;
			}
			else if (signature[i] == "10"){
				category = 10;
			}
			else if (signature[i] == "11"){
				category = 11;
			}
			else {
				
				//cout << signature[i] << endl;
				//scan line until all functions have been scanned
				while ((offset = content[lineno].find(signature[i], wall)) != string::npos) {
					startPos = offset;
					offset = offset + signature[i].size();
					wall = offset+1;
					
					//condition that checks for words that may be wrongly detected as a dangerous function
					if (startPos !=0) {
						if ((content[lineno][startPos-1]>=65 && content[lineno][startPos-1]<=90) ||
											(content[lineno][startPos-1]>=97 && content[lineno][startPos-1]<=122) ||
											(content[lineno][startPos-1]>=48 && content[lineno][startPos-1]<=57) ||
											(content[lineno][startPos-1] == '_')) {
							continue;
						}
					}
					if ((content[lineno][offset]>=65 && content[lineno][offset]<=90) ||
											(content[lineno][offset]>=97 && content[lineno][offset]<=122) ||
											(content[lineno][offset]>=48 && content[lineno][offset]<=57) ||
											(content[lineno][offset] == '_')) {
						continue;
					}
					//category 7 holds the ways that asp can accept user input
					//detects the methods and store the user input for detection
					if ((signature[i] == "end function") || (signature[i] == "end sub")) {
						function = false;
						functionVariable.erase(functionVariable.begin(), functionVariable.end());
						fline.erase(fline.begin(), fline.end());
					}
					else if ((signature[i] == "function") || (signature[i] == "sub")) {
					
						
						
						if (content[lineno][offset] != ' ') {
							
							continue;
						}
						else if (content[lineno].find("{", 0) != string::npos) {
							continue;
						}
						else {
							
							offset++;
							functionName = "";
							while (content[lineno][offset] != '(') {
								functionName = functionName + content[lineno][offset];
								offset++;
								
							}
							variable = "";
							while (content[lineno][offset] != ')') {
								variable = variable + content[lineno][offset];
								offset++;
								if ((content[lineno][offset] == ',') || (content[lineno][offset] == ')')) {
									functionVariable.push_back(variable);
									fline.push_back(lineno);
								}
								
								
							}
							
							function = true;
						}
					}
					else if (category == 7) {	 	 
						variable = "";
						//obtain user input from a form
						if (signature[i] == "<input") {
							found = false;
							variable = "";
							
							while ( lineno < content.size()) {
								//determine the type of form, may ignore some types
								if ((offset1 = content[lineno].find("type=", wall)) != string::npos) {
									offset1 = offset1+5;
									if (content[lineno][offset1] == '\"') {
										stack.push_back('\"');
										while (stack.size() != 0) {
											offset1++;
											if (content[lineno][offset1] == '\"')
												stack.pop_back();
											else
												variable.append(1, content[lineno][offset1]);
										}
											
									}
									else {
										while ((content[lineno][offset1]>=65 && content[lineno][offset1]<=90) ||
												(content[lineno][offset1]>=97 && content[lineno][offset1]<=122) ||
												(content[lineno][offset1] == '_') && (offset < content[lineno].size())) {
											variable.append(1, content[lineno][offset1]);
											offset1++;
										}
									}
									//types to ignore
									if (variable == "submit") {
										found = false;
										break;
									}
									else if (variable == "reset") {
										found = false;
										break;
									}
									else {
										//find the assignment of the variable
										variable = "";
										while ( lineno < content.size()) {
											if ((offset1 = content[lineno].find("name=", wall)) != string::npos) {
												offset1 = offset1+5;
												wall = offset+1;
												found = true;
												break;
											}
											else if ((offset1 = content[lineno].find("id=", wall)) != string::npos) {
												offset1 = offset1+3;
												wall = offset+1;
												found = true;
												break;
											}
											else {
												lineno++;
												wall=0;
											}
										}
										if (found)
											break;	    
									}
								} 
								else {
									lineno++;
								}	 	 	 	   	   	   	   	   	   	   	   	   	   	   	   	   	   	   	   	   	    	   	   	   	   	    	      	   	   
							}
							//if found, obtain the variable name
							if (found) {
								//obtain variable name if enclosed in quotes
								if (content[lineno][offset1] == '\"') {
									stack.push_back('\"');
									while (stack.size() != 0) {
										offset1++;
										if (content[lineno][offset1] == '\"')
											stack.pop_back();
										else
											variable.append(1, content[lineno][offset1]);
									}
										
								}
								//obtain variable name normally
								else {
									while ((content[lineno][offset1]>=65 && content[lineno][offset1]<=90) ||
											(content[lineno][offset1]>=97 && content[lineno][offset1]<=122) ||
											(content[lineno][offset1] == '_') && (offset < content[lineno].size())) {
										variable.append(1, content[lineno][offset1]);
										offset1++;
									}
								}
								//store the variable and its lineno
								variables.push_back(variable);
								vline.push_back(lineno);
								userInput.push_back(variable);
							} 	  	  	  	  	   	   	   	   	   	   
						}
						//obtain user input from request methods, cookies, form, or querystring
						else if ((signature[i] == "request.cookies") || (signature[i] == "request.form") || (signature[i] == "request.querystring")) {
							if (signature[i] == "request.cookies")
								variable = "request.cookies";
							else if (signature[i] == "request.form")
								variable = "request.form";
							else if (signature[i] == "request.querystring")
								variable = "request.querystring";
							
							//obtaining the full request statement
							while ((content[lineno][offset] != ' ') && (offset < content[lineno].size())) {
								if (content[lineno][offset] == '(') {
									stack.push_back(content[lineno][offset]);
									variable.append(1, content[lineno][offset]);
									while (stack.size() != 0) {
										offset++;
										if (content[lineno][offset] == ')') {
											stack.pop_back();
											variable.append(1, content[lineno][offset]);
										}
										else
											variable.append(1, content[lineno][offset]);						
									}
								}
								else
									break;
							}
							found = false;
							assign = true;
							//add to user input list if haven't already
							if (variablesUsed.size() !=0) {
								for (int j=0; j<variablesUsed.size(); j++) {
									if (variablesUsed[j] == variable) {
										found = true;
										break;
									}
								}
								if (!found) {
									if (function) {
										functionVariable.push_back(variable);
										variablesUsed.push_back(variable);
										fline.push_back(lineno);
									}
									else {
										variables.push_back(variable);
										vline.push_back(lineno);
										userInput.push_back(variable);
										variablesUsed.push_back(variable);
									}
								}
							}
							else {
								if (function) {
									functionVariable.push_back(variable);
									variablesUsed.push_back(variable);
									fline.push_back(lineno);
								}
								else {
									variables.push_back(variable);
									vline.push_back(lineno);
									userInput.push_back(variable);
									variablesUsed.push_back(variable);
								}
							}
							
							//if user input detected is new, try to obtain the variable it is assigned to
							if (!found) {
								offset = startPos;
								//checking if user input is assigned to a variable
								while (content[lineno][offset] != '=') {
									offset--;
									if ((offset<0) || (content[lineno][offset] == ',')
										|| (content[lineno][offset] == '(')) {
										assign = false;
										break;
									}
								}
								//if variable was assigned to a variable, obtain that variable
								if (assign) {
									offset--;
									if (content[lineno][offset] == ' ')
										offset--;
									
									variable = "";
									//2nd check to see if user input was assigned to a variable
									while ((content[lineno][offset] != ' ') 
											&& (offset >=0)) {
										
										variable = content[lineno][offset] + variable;
										offset--;
										if (content[lineno][offset] == '.') {
											assign = false;
											break;
										}
										
									}
									//add obtained variable to the list, if haven't already
									if (assign) {
										found = false;
										if (variablesUsed.size() !=0) {
											for (int j=0; j<variablesUsed.size(); j++) {
												if (variablesUsed[j] == variable) {
													found = true;
													break;
												}
											}
											if (!found) {
												if (function) {
													functionVariable.push_back(variable);
													variablesUsed.push_back(variable);
													fline.push_back(lineno);
												}
												else {
													variables.push_back(variable);
													vline.push_back(lineno);
													userInput.push_back(variable);
													variablesUsed.push_back(variable);
												}
											}
										}
										else {
											if (function) {
												functionVariable.push_back(variable);
												variablesUsed.push_back(variable);
												fline.push_back(lineno);
											}
											else {
												variables.push_back(variable);
												vline.push_back(lineno);
												userInput.push_back(variable);
												variablesUsed.push_back(variable);
											}
										}
									}
								}
							}
						}
						
						//obtain user input from text box
						else if (signature[i] == ".text") {
							variable = ".text";
							while ((content[lineno][offset] != ' ') 
									&& (offset >=0)) {
										
								variable = content[lineno][offset] + variable;
								offset--;	 	 	 	 	 	 	 
							}
							//add variable obtained into user input list, if haven't already
							found = false;
							assign = true;
							if (variablesUsed.size() !=0) {
								for (int j=0; j<variablesUsed.size(); j++) {
									if (variablesUsed[j] == variable) {
										found = true;
										break;
									}
								}
								if (!found) {
									if (function) {
										functionVariable.push_back(variable);
										variablesUsed.push_back(variable);
										fline.push_back(lineno);
									}
									else {
										variables.push_back(variable);
										vline.push_back(lineno);
										userInput.push_back(variable);
										variablesUsed.push_back(variable);
									}
								}
							}
							else {
								if (function) {
									functionVariable.push_back(variable);
									variablesUsed.push_back(variable);
									fline.push_back(lineno);
								}
								else {
									variables.push_back(variable);
									vline.push_back(lineno);
									userInput.push_back(variable);
									variablesUsed.push_back(variable);
								}
							}
							// if user input is new, check if it is assigned to a variable
							if (!found) {
								while (content[lineno][offset] != '=') {
									offset--;
									if ((offset<0) || (content[lineno][offset] == ',')
										|| (content[lineno][offset] == '(')) {
										assign = false;
										break;
									}
								}
								//if it is, obtain the variable
								if (assign) {
									offset--;
									if (content[lineno][offset] == ' ')
										offset--;
									
									variable = "";
									while ((content[lineno][offset] != ' ') 
											&& (offset >=0)) {
										
										variable = content[lineno][offset] + variable;
										offset--;
										//2nd check to see if user input is assigned to a variable
										if (content[lineno][offset] == '.') {
											assign = false;
											break;
										}
										
									}
									//if variable is obtained, add it to the user input list, if haven't already
									if (assign) {
										found = false;
										if (variablesUsed.size() !=0) {
											for (int j=0; j<variablesUsed.size(); j++) {
												if (variablesUsed[j] == variable) {
													found = true;
													break;
												}
											}
											if (!found) {
												if (function) {
													functionVariable.push_back(variable);
													variablesUsed.push_back(variable);
													fline.push_back(lineno);
												}
												else {
													variables.push_back(variable);
													vline.push_back(lineno);
													userInput.push_back(variable);
													variablesUsed.push_back(variable);
												}
											}
										}
										else {
											if (function) {
												functionVariable.push_back(variable);
												variablesUsed.push_back(variable);
												fline.push_back(lineno);
											}
											else {
												variables.push_back(variable);
												vline.push_back(lineno);
												userInput.push_back(variable);
												variablesUsed.push_back(variable);
											}
										}
									}
								}
							}	 	 	 
						}
						//check if variable has been validated using controltovalidate methods
						else if (signature[i] == "controltovalidate") {
							//obtain the variable being validated
							variable="";
							if (variables.size() != 0) {
								offset++;
								if (offset >= content[lineno].size() ) {
									lineno++;
									offset=0;
									wall = 0;
								}
								if (content[lineno][offset] == '\"') {
									stack.push_back('\"');
									while (stack.size() != 0) {
										offset++;
										if (content[lineno][offset] == '\"')
											stack.pop_back();
										else
											variable.append(1, content[lineno][offset]);
									}
										
								}
								else {
									while ((content[lineno][offset]>=65 && content[lineno][offset]<=90) ||
											(content[lineno][offset]>=97 && content[lineno][offset]<=122) ||
											(content[lineno][offset] == '_') && (offset < content[lineno].size())) {
										
										variable.append(1, content[lineno][offset]);
										offset++;
									}
								}
								//check variable obtained against existing variable list.
								//remove variable from list if match is found
								k=0;
								while (k<variables.size()) {
									if (variables[k] == variable) {
										variables.erase(variables.begin()+k);
										break;
									}
									k++;
								}
							}
						}
						//check if variable is validated using .ismatch method
						else if (signature[i] == ".ismatch") {
							variable="";
							//obtain the variable being validated
							if (variables.size() != 0) {
								offset++;
								if (offset >= content[lineno].size() ) {
									lineno++;
									offset=0;
									wall=0;
								}
								if (content[lineno][offset] == '\"') {
									stack.push_back('\"');
									while (stack.size() != 0) {
										offset++;
										if (content[lineno][offset] == '\"')
											stack.pop_back();
										else
											variable.append(1, content[lineno][offset]);
									}
										
								}
								else {
									while ((content[lineno][offset]>=65 && content[lineno][offset]<=90) ||
											(content[lineno][offset]>=97 && content[lineno][offset]<=122) ||
											(content[lineno][offset] == '_') && (offset < content[lineno].size())) {	   	   	   	   	   	   	   	   	   
										variable.append(1, content[lineno][offset]);
										offset++;						
									}
								}
								//check variable obtained against existing variable list.
								//remove variable from list if match is found
								k=0;
								while (k<variables.size()) {
									if (variables[k] == variable) {	   	   	   	   	   	   	   	   
										variables.erase(variables.begin()+k);
										break;
									}
									k++;
								}
							}
						}
					}
					//check for file system functions.
					//may allow an attacker to upload and/or delete files from the server
					else if (category == 8) {
						//check if user input is used as an argument for file system operations
						for (int j=0; j<variablesUsed.size(); j++) {
							if ((offset = content[lineno].find(variablesUsed[j], 0)) != string::npos) {
								if (function) {
									
									if (signature[signature.size()-1] == functionName) {
										
										aspComments[aspComments.size()-1] = aspComments[aspComments.size()-1] + "\nIt also contains the use "
																"of dangerous file system functions using the arguments of the function.";
									}
									else {
										
										signature.push_back(functionName);
										functionName = "User-defined Function \"" +functionName + "\"";
										aspComments.push_back(functionName);
										aspComments.push_back("This is a user-defined function. It contains the use "
																"of dangerous file system functions using the arguments of the function.");
									}
								}
								else {
									temp = "File System Method \"" + signature[i] + "\"";
									r.addDangerFunctions(temp, 5, lineno);
								}
								
							}
						}
					}
					//check for script objects WSCRIPT.SHELL and WSCRIPT.NETWORK
					else if (category == 9) {
						
						//reads the name of the object created and adds it to the danger functions list
						while (content[lineno][offset] != '=') {
							offset--;
							/*if (offset<0) {
								lineno--;
								offset = content[lineno].size()-1;
							}*/
						}
						offset--;
						if (content[lineno][offset] == ' ')
							offset--;
							
						variable = "";
						while ((content[lineno][offset] != ' ') 
								&& (offset >=0)) {
							variable = content[lineno][offset] + variable;
							offset--;
							
						}
						
						signature.push_back(variable);
						commandVariable.push_back(variable);
							
					}
					//checks for use of Process objects
					else if (category == 10) {
						while (content[lineno][offset] != '=') {
							offset++;
							/*if (offset<0) {
								lineno--;
								offset = content[lineno].size()-1;
							}*/
						}
						offset++;
						if (content[lineno][offset] == ' ')
							offset++;
						
						//obtain the content being passed in to the process attributes
						variable = "";
						while ((content[lineno][offset] != ' ') 
								&& (offset <content[lineno].size())) {
							variable = variable + content[lineno][offset];
							offset++;
							
						}
						//add it to the results list if content is found to be a user input
						found = false;
						if (variablesUsed.size() !=0) {
							for (int j=0; j<variablesUsed.size(); j++) {
								if (variablesUsed[j] == variable) {
									found = true;
									break;
								}
							}
							if (found) {
								if (function) {
									if (signature[signature.size()-1] == functionName) {

										aspComments[aspComments.size()-1] = aspComments[aspComments.size()-1] + "\nIt also contains the use "
																"of dangerous Process functions using the arguments of the function.";
									}
									else {
										signature.push_back(functionName);
										aspComments.push_back(functionName);
										aspComments.push_back("This is a user-defined function. It contains the use "
																"of dangerous Process functions using the arguments of the function.");
									}
								}
								else {
									temp = "Process variable \"" + signature[i] +"\"";
									r.addDangerFunctions(temp, 7, lineno);
								}
							}
						}
					}
					//check for use of the script objects created
					else if (category == 11) {
						
						found = false;
						//if user input is found to be used in these objects, add it to the results list
						for (int j=0; j<variablesUsed.size(); j++) {
							if ((offset = content[lineno].find(variablesUsed[j], wall)) != string::npos) {
								for (int h=0; h<commandVariable.size(); h++) {
									if (commandVariable[h] == variablesUsed[j])  {
										found = true;
										if (function) {
											if (signature[signature.size()-1] == functionName) {
		
												aspComments[aspComments.size()-1] = aspComments[aspComments.size()-1] + "\nIt also contains the use "
																		"of dangerous command functions using the arguments of the function.";
																
											}
											else {
												signature.push_back(functionName);
												aspComments.push_back(functionName);
												aspComments.push_back("This is a user-defined function. It contains the use "
																		"of dangerous Process functions using the arguments of the function.");
											}
										}
										else {
											temp = "Command Object \"" + signature[i] +"\"";
											r.addDangerFunctions(temp, 7, lineno);
										}
										break;
									} 
								}
								if (!found) {
									r.addDangerFunctions(signature[i], 7, lineno);
								}
							}
						}
					}	 	 
				}
			}
			i++;
		}
		
		lineno++;	 
	}
	/*if (userInput.size() !=0) {
		for (int j=0; j<variables.size(); j++)
			cout << userInput[j] << " not validated" << endl;
	}*/
	cout << endl;
	score = r.calculateScore();
	if (score > 0)
		r.printResults();
}

//function to scan jsp files
void FileScanner::scanJSP(vector<string> signature) {

	ifstream fileInput;
	int offset, offset1;
	int lineno = 0;
	int wall = 0;
	int startPos;
	int i=0;
	int k=0;
	int category, score;
	string line, variable, temp;
	vector<char> stack;
	vector<string> content;
	vector<string> variables;
	vector<string> userInput;
	vector<int> vline;
	bool found = false;
	bool assign = false;
	Results r(cfilename, logfile, ".jsp");

	//retrieving file content
	fileInput.open(cfilename.c_str());
	if(fileInput.is_open()) {
		while(getline(fileInput, line)) {
			content.push_back(line);
		}
		fileInput.close();
	}
	else cout << "Unable to open file.";
	
	//loop to scan each line
	while(lineno < content.size()) {
		i=0;
		wall = 0;
		//loop to check line for any assignment of user input
		while(i<userInput.size()) {
			while ((offset = content[lineno].find(userInput[i], wall)) != string::npos) {
			
				startPos = offset;
				wall = offset+1;
				assign = true;
				k = lineno;
				//check for assignment of variable value
				while (content[k][offset] != '=') {
					offset--;
					if (offset < 0 ) {
						k--;
						offset=content[k].size()-1;
					}
					if ((content[k][offset] == ',')
						|| (content[k][offset] == '(')) {
						assign = false;
						break;
					}
				}
				//if assignment is taking place, scan for the variable in question
				if (assign) {
					offset--;
					while ((content[k][offset] == ' ') || (content[k][offset] == '\n')
						|| (content[k][offset] == '\t')) {
						offset--;
						if (offset < 0 ) {
							k--;
							offset=content[k].size()-1;
						}
					}
					//obtain the variable	 	 	 	 
					variable = "";
					while ((content[k][offset]>=65 && content[k][offset]<=90) ||
											(content[k][offset]>=97 && content[k][offset]<=122) ||
											(content[k][offset] == '_')) {
										
						variable = content[k][offset] + variable;
						offset--;
						/*if (offset < 0 ) {
							k--;
							offset=content[k].size()-1;
						}*/ 		
					}
					//add the variable to the user input list, if haven't already
					found = false;
					if (variables.size() !=0) {
						for (int j=0; j<userInput.size(); j++) {
							if (userInput[j] == variable) {
								found = true;
								break;
							}
						}
						if (!found) {
							variables.push_back(variable);
							vline.push_back(lineno);
							userInput.push_back(variable);
						}
					}
					else {
						variables.push_back(variable);
						vline.push_back(lineno);
						userInput.push_back(variable);
					}	 
				}
			}
			i++;
		}
		
		i = 0;
		wall=0;
		//loop to scan line for dangerous functions
		while(i<signature.size()) {
			
			if (signature[i] == "11") {
				category = 11;
			}
			else if (signature[i] == "12") {
				category = 12;
			}
			else if (signature[i] == "13"){
				category = 13;
			}
			
			else {
				//continue scanning line until entire line is cleared of all dangerous functions
				while ((offset = content[lineno].find(signature[i], wall)) != string::npos) {
					startPos = offset;
					wall = offset + signature[i].size();
					//checks for category 11, which holds the scanner objects that a user can use
					//to obtain user input
					if (category == 11) {
						assign = false;
						k = lineno;
						while ((content[k][offset] != '=')
								&& (content[k][offset] != '(')) {
							offset--;
							if (offset < 0 ) {
								k--;
								offset=content[k].size()-1;
							}
						}
							
						//checking for assignment
						if (content[k][offset] == '=')
							assign = true;
						else
							assign = false;
						
						//if it was assigned to a variable, obtain the variable
						if (assign) {
							if (content[k][offset] == ' ') {
								offset--;
								if (offset < 0 ) {
									k--;
									offset=content[k].size()-1;
								}
							}
							
							variable = "";
							found = false;
							while (content[k][offset] != ' ') {
								variable = content[k][offset] + variable;
								offset--;
								if (offset < 0 ) {
									k--;
									offset=content[k].size()-1;
								}
							}
							//add the obtained variable to the user input list, if haven't already
							if (userInput.size() !=0) {
								for (int j=0; j<userInput.size(); j++) {
									if (userInput[j] == variable) {
										found = true;
										break;
									}
								}
								if (!found) {
									userInput.push_back(variable);
								}
							}
							else {
								
								userInput.push_back(variable);
							}
						}
					}
					//category 12 holds functions used to obtain user input
					else if (category == 12) {
						k = lineno;
						//obtain variable
						while (content[k][offset] != '=') {
							offset--;
							if (offset < 0 ) {
								k--;
								offset=content[k].size()-1;
							}
						}
						offset--;
						if (offset < 0 ) {
							k--;
							offset=content[k].size()-1;
						}
						
						if (content[lineno][offset] == ' ') {
							offset--;
							if (offset < 0 ) {
								k--;
								offset=content[k].size()-1;
							}
						}
						
						variable = "";
						
						while (content[k][offset] != ' ') {
							variable = content[k][offset] + variable;
							offset--;
							if (offset < 0 ) {
								k--;
								offset=content[k].size()-1;
							}
						}
						
						//for getParameter method, the variable holds the user input
						//but for scanner and bufferedreader, the variable is a scanner object
						//that will be used to obtain the user input
						if (signature[i] == "getParameter") {
							userInput.push_back(variable);
						}
						else {
							found = false;
							if (variables.size() !=0) {
								for (int j=0; j<variables.size(); j++) {
									if (variables[j] == variable) {
										
										found = true;
										break;
									}
								}
								if (!found) {
									variables.push_back(variable);
									signature.insert(signature.begin()+1, variable);
									if (signature[i] == "new Scanner")
										variable = variable + ".next";
									else if (signature[i] == "new BufferedReader")
										variable = variable + ".read";
									
									
									userInput.push_back(variable);
									
								}
							}
							else {
								variables.push_back(variable);
								signature.insert(signature.begin()+1, variable);
								if (signature[i] == "new Scanner")
									variable = variable + ".next";
								else if (signature[i] == "new BufferedReader")
									variable = variable + ".read";
								userInput.push_back(variable);
							}
						}
						
					}
					//category 13 holds the actual dangerous functions
					else if (category == 13) {
						offset = offset + signature[i].size();
						if (content[lineno][offset] == '(') {
							offset++;
							if (offset >= content[lineno].size() ) {
								lineno++;
								offset=0;
								wall = 0;
							}
							stack.push_back(content[lineno][offset]);
							variable = "";
							while (stack.size() != 0) {
								if (content[lineno][offset] == ')')
									stack.pop_back();
								else {
									variable = variable + content[lineno][offset];
									offset++;
									if (offset >= content[lineno].size() ) {
										lineno++;
										offset=0;
										wall = 0;
									}
								}
							}
							//determine if user input was used within those dangerous functions
							//add it to the results list if so.
							for (int j=0; j<userInput.size(); j++) {
								if ((offset1 = variable.find(userInput[j], 0)) != string::npos) {
									startPos = offset1;
									offset1 = offset1 + userInput[j].size();
									if (offset1 < variable.size()) {
										if (startPos !=0) {
											if ((variable[startPos-1]>=65 && variable[startPos-1]<=90) ||
																(variable[startPos-1]>=97 && variable[startPos-1]<=122) ||
																(variable[startPos-1]>=48 && variable[startPos-1]<=57) ||
																(variable[startPos-1] == '_')) {
												continue;
											}
										}
										if ((variable[offset1]>=65 && variable[offset1]<=90) ||
																(variable[offset1]>=97 && variable[offset1]<=122) ||
																(variable[offset1]>=48 && variable[offset1]<=57) ||
																(variable[offset1] == '_')) {
											continue;
										}
									}
									if (userInput[j].size() != 0)  
										r.addDangerFunctions(signature[i], 5, lineno);
								}
							}
						}
					}
				}
			}
			i++;
		}
		
		lineno++;
	}
	
//	  for (int j=0; j< userInput.size(); j++)
//	  	  cout << userInput[j] << endl;
	
	cout << endl;
	score = r.calculateScore();
	if (score > 0)
		r.printResults();
}


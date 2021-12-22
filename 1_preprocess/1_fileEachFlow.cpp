#include <iostream>
#include <algorithm>
#include <filesystem>
#include <string> 
#include <vector>
#include <thread>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <regex>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include<bits/stdc++.h>

/*
    warning:
        you need to type "ulimit -n <max file descriptor size>" before runnig this program.
*/

using namespace std;

typedef long long int ll;

struct fiveTuple_s
{    
    string srcIP;
    string srcPort;
    string dstIP;
    string dstPort;    
    string proto;
    string malwareType;
};

enum catch_files_mode_e {
    /*
    only_nonfixed_pcap : has executed "pcapfix" command
    only_fixed_pcap : has executed  "splitcap" command
    */
    anything = 0, only_nonfixed_pcap = 1, only_fixed_pcap = 2
}; 

map<string, string> pcap_special_type = {{"fixed", "fixed_"}, {"pcap", "p_"}};
const vector<string> type_order = {"normal", "scanning", "DoS", "Injection",
                                        "DDoS", "password", "XSS",
                                        "ransomware", "backdoor", "MITM"};
// Test Path
// const string ROOT_DIR_PATH = "/home/redduck/Downloads/dataset/script/test_dataset";
// const string LABEL_DIR_PATH = "/home/redduck/Downloads/dataset/script/test_dataset_label";

// Real Path
const string ROOT_DIR_PATH = "/home/redduck/Downloads/dataset/Raw_Network_dataset/Network_dataset_pcaps/normal_attack_pcaps";
const string LABEL_DIR_PATH = "/home/redduck/Downloads/dataset/Processed_Network_dataset";
const string STORE_NORMAL_IN_MAL_DIR = "/home/redduck/Downloads/dataset/script/normal_pcap_file_from_malware";

const string SPLITCAP_EXE_PATH = "/home/redduck/Downloads/mono/SplitCap.exe";
const string MAX_FILE_DESCRIPTOR_NUMBER = "5000";
const int MAX_PCAP_SIZE = 500; //MB
const int MAX_SPLIT_FIVE_TUPLE_PCAP_CHILD_PROCESS = 3;

void get_dirs(vector<filesystem::path> &dirs, string dir_path);
void get_files(vector<filesystem::path> &files, string dir_path, bool getPcap=false, string prefix="");
void fix_pcap_files(string dir_path);
void pcapng_files_to_pcap_files(string dir_path);
bool compare_filename_with_number(filesystem::path p1, filesystem::path p2);
void remove_control_whitespace_characters(string &s);

void update_label_five_tuple_set(set<string> &label_fiveTuple_set, string filePath);
void generate_small_pcaps_according_to_five_tuple(string dir_path, string malware_tpye, set<string> &label_fiveTuple_set, map<string, ll> &sample_statistic);
string parse_small_pcap_file_name(string file_name, string malware_type, bool order_src_dst=true);
void reduceSize_pcap(const filesystem::path &dir_path, string malware_type);

void remove_control_whitespace_characters(string &s) 
{
    s.erase(std::remove_if(s.begin(), s.end(), [](char c) { return std::iscntrl(c); }), s.end());
    s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());
}

bool compare_filename_with_number(filesystem::path p1, filesystem::path p2)
{
    int n1, n2;
    string str1, str2;
    str1 = p1.stem();
    str2 = p2.stem();
    
    regex reg("[0-9]+$");
    smatch m;
    n1 = (regex_search(str1, m, reg) && !m.empty()) ? stoi(m.str(0)) : 0;
    n2 = (regex_search(str2, m, reg) && !m.empty()) ? stoi(m.str(0)) : 0;
    
    return n1 < n2;
}

void get_dirs(vector<filesystem::path> &dirs, string dir_path)
{    
    dirs.clear();
    for (const auto &entry : filesystem::directory_iterator(dir_path)) {
        if (entry.is_directory())           
            dirs.push_back(entry.path());                        
    }
}

void get_files(vector<filesystem::path> &files, string dir_path, bool getPcap, string prefix)
{
    /*
        getPcap =  
            false : only catch nonfixed pcap files
            true : catch pcap files            
        prefix = 
            "" : get non-special pcap files
            "..." : get specific prefix of pcap files (e.g., fixed_....pcap) 
    */
    files.clear();
    for (const auto &entry : filesystem::directory_iterator(dir_path)) {
        if (entry.is_regular_file()) {  
            auto p = entry.path();      
            if (getPcap) {
                if (string(p.extension()).compare(".pcap") != 0)
                    continue;

                string str_filename = p.filename();
                if (prefix.compare("") != 0) {
                    regex reg("^" + prefix);                    
                    smatch m;
                    regex_search(str_filename, m, reg);
                    if (m.empty())
                        continue;
                } else {                    
                    bool is_special_type = false;
                    for (auto stype : pcap_special_type) {
                        regex reg("^" + stype.second);
                        smatch m;
                        regex_search(str_filename, m, reg);
                        if (!m.empty()) {
                            is_special_type = true;
                            break;
                        }                        
                    }    
                    if (is_special_type) continue;                    
                }
            }

            files.push_back(p);
        }
    }
}

void fix_pcap_files(string dir_path)
{
    while (true) {
        bool canbreak = true;

        vector<filesystem::path> files;

        //get all non-special pcap files
        get_files(files, dir_path, true);

        // run pcapfix command per file
        string tmp = filesystem::current_path();
        filesystem::current_path(dir_path);
        vector<pid_t> childs;    
        for (auto file_path : files) {
            pid_t pid;         
            if ((pid = fork()) == 0)          
                execl("/bin/pcapfix", "pcapfix", string(file_path).c_str(), NULL);
            else             
                childs.push_back(pid);        
        }
        filesystem::current_path(tmp);

        // wait all child completed
        for (auto &child : childs)
            waitpid(-1, NULL, 0);

        // rename the non-fixed files and delete broken files    
        for (auto file_path : files) {
            filesystem::path fixed_file_path(string(file_path.parent_path()) + "/fixed_" + string(file_path.filename()));            

            if (filesystem::exists(fixed_file_path)) {
                filesystem::remove(file_path);
                filesystem::rename(fixed_file_path, file_path);
                canbreak = false;                
            }
        }
        
        
        if (canbreak) {
            // It means that the all file name don't have "fixed" in prefix. => fix file process OK.
            for (auto file_path : files) {
                filesystem::path fixed_file_path(string(file_path.parent_path()) + "/fixed_" + string(file_path.filename()));
                filesystem::rename(file_path, fixed_file_path);
            }
            break;
        }
    }
}

void pcapng_files_to_pcap_files(string dir_path)
{
    // must first run "fix_pcap_files" function

    vector<filesystem::path> files;

    // get all fixed pcap files
    get_files(files, dir_path, true, pcap_special_type["fixed"]);

    // run edit command per file (pcapng -> pcap process)
    string tmp = filesystem::current_path();
    filesystem::current_path(dir_path);
    vector<pid_t> childs;    
    for (auto file_path : files) {
        pid_t pid;                         
        if ((pid = fork()) == 0)          
            execl("/bin/editcap", "editcap", "-F", "libpcap", file_path.filename().c_str()
                    , (pcap_special_type["pcap"] + string(file_path.filename())).c_str(), NULL);
        else             
            childs.push_back(pid);        
    }
    filesystem::current_path(tmp);

    for (auto &child : childs)
        waitpid(-1, NULL, 0);
    
    // remove the original files
    for (auto file_path : files) 
        filesystem::remove(file_path);
}

map<string, ll> stats; //!! malware statistic 
void update_label_five_tuple_set(set<string> &label_fiveTuple_set, string filePath)
{
    fstream fsin(filePath);
    string line;        

    getline(fsin, line);    
    while (getline(fsin, line)) {    
        //one entry to multiple fields           
        vector<string> fields;
        string field;
        stringstream ss(line);
        while (getline(ss, field, ',')) {
            remove_control_whitespace_characters(field);
            fields.push_back(field);
        }
        
        // start to statistic (according same session)   
        // only get tcp or udp packets
        if (!(fields[5].compare("tcp") == 0 || fields[5].compare("udp") == 0))
            continue;
        string tmp1 = fields[1] + "_" + fields[2] + "_" + fields[3] + "_" + fields[4] + "_" + fields[5] + "_" + fields[/*6*/44];  
        string tmp2 = fields[3] + "_" + fields[4] + "_" + fields[1] + "_" + fields[2] + "_" + fields[5] + "_" + fields[/*6*/44];            
        set<string>::iterator it1 = label_fiveTuple_set.find(tmp1);
        set<string>::iterator it2 = label_fiveTuple_set.find(tmp2);
        if (it1 == label_fiveTuple_set.end() && it2 == label_fiveTuple_set.end()) {
            label_fiveTuple_set.insert(tmp1);                                
            stats[fields[/*6*/44]]++;  //!!  malware statistic    
        }
        
    }
}

string parse_small_pcap_file_name(string file_name, string malware_type, bool order_src_dst)
{
    fiveTuple_s tmp;
    string five_tuple = file_name.substr(file_name.find(".pcap") + 6,
                                                    (file_name.rfind(".pcap") - (file_name.find(".pcap") + 6)));
    stringstream ss;    
    ss << five_tuple;

    getline(ss, tmp.proto, '_'); 
    getline(ss, tmp.srcIP, '_');
    getline(ss, tmp.srcPort, '_');   
    getline(ss, tmp.dstIP, '_');
    getline(ss, tmp.dstPort, '_');
    tmp.malwareType = malware_type;
    

    transform(tmp.proto.begin(), tmp.proto.end(), tmp.proto.begin(), ::tolower);
    replace(tmp.srcIP.begin(), tmp.srcIP.end(), '-', '.');
    replace(tmp.dstIP.begin(), tmp.dstIP.end(), '-', '.');
    
    string ret = "";
    if (order_src_dst)
        ret += tmp.srcIP + "_" + tmp.srcPort + "_" + tmp.dstIP + "_" + tmp.dstPort;
    else
        ret += tmp.dstIP + "_" + tmp.dstPort + "_" + tmp.srcIP + "_" + tmp.srcPort;
    
    ret += + "_" + tmp.proto + "_" + tmp.malwareType;        
    
    return ret;
}

void generate_small_pcaps_according_to_five_tuple(string dir_path, string malware_tpye, set<string> &label_fiveTuple_set, map<string, ll> &sample_statistic)
{
    // must run "pcapng_files_to_pcap_files" function

    vector<filesystem::path> files;

    // get all fixed pcap files
    get_files(files, dir_path, true, pcap_special_type["pcap"]);
    // rename all fixed pcap files
    for (auto file : files) {        
        filesystem::path ori_file_name(string(file.parent_path()) + "/subdir_" + string(file.filename()).substr(8)); 
        cout << ori_file_name << endl;
        filesystem::rename(file, ori_file_name);
    }

    
    // get all pcap files again
    get_files(files, dir_path, true);
    // run splitCap.exe  per file (split to many small pcap according to 5-tuple)
    string tmp = filesystem::current_path();
    filesystem::current_path(dir_path);
    vector<pid_t> childs;    
    for (auto file_path : files) {
        // a lot of child processes will crash the system.
        if (childs.size() >= MAX_SPLIT_FIVE_TUPLE_PCAP_CHILD_PROCESS) {
            for (auto &child : childs)
                waitpid(-1, NULL, 0);
            childs.clear();
        }

        pid_t pid;                   
        if ((pid = fork()) == 0)          
            execl(SPLITCAP_EXE_PATH.c_str(), SPLITCAP_EXE_PATH.c_str(),
                    "-r", file_path.filename().c_str(), "-p", MAX_FILE_DESCRIPTOR_NUMBER.c_str(), NULL);       
        else             
            childs.push_back(pid);        
    }
    filesystem::current_path(tmp);
    for (auto &child : childs)
        waitpid(-1, NULL, 0);
    
    // add new entry(e.g., malware type) to smaple_statistic
    transform(malware_tpye.begin(), malware_tpye.end(), malware_tpye.begin(), ::tolower);
    sample_statistic.insert(pair<string, ll>(malware_tpye, 0));
    
    // rename original pcap file (delete subdir_ prefix)
    for (auto file : files) {        
        filesystem::path ori_file_name(string(file.parent_path()) + "/" + string(file.filename()).substr(7));         
        filesystem::rename(file, ori_file_name);
    }


    // delete normal pcap files   
    vector<filesystem::path> small_pacp_dirs;
    get_dirs(small_pacp_dirs, dir_path);
    sort(small_pacp_dirs.begin(), small_pacp_dirs.end(), compare_filename_with_number);    
    for (auto pcap_dir : small_pacp_dirs) {
        cout << "\tpcap path:" << pcap_dir << endl;
        vector<filesystem::path> small_pcap_files;
        get_files(small_pcap_files, pcap_dir, true);
        for (auto pcapfile : small_pcap_files) {            
            string tmp = parse_small_pcap_file_name(pcapfile.filename(), malware_tpye);            
            set<string>::iterator it = label_fiveTuple_set.find(tmp);
            if (it != label_fiveTuple_set.end()) {                   
                label_fiveTuple_set.erase(it);    
                sample_statistic[malware_tpye]++;                                    
            } else {
                tmp = parse_small_pcap_file_name(pcapfile.filename(), malware_tpye, false);
                it = label_fiveTuple_set.find(tmp);
                if(it != label_fiveTuple_set.end()) {
                    label_fiveTuple_set.erase(it);
                    sample_statistic[malware_tpye]++;                    
                } else {
                    //move normal traffic file which is in malware file to specific normal directory
                    string tmp2 = parse_small_pcap_file_name(pcapfile.filename(), "normal");
                    it = label_fiveTuple_set.find(tmp2);
                    if (it != label_fiveTuple_set.end()) {
                        label_fiveTuple_set.erase(it);
                        sample_statistic["normal"]++;
                        filesystem::rename(pcapfile, filesystem::path(STORE_NORMAL_IN_MAL_DIR + "/" + pcapfile.filename().string()));                         
                    } else{
                        string tmp2 = parse_small_pcap_file_name(pcapfile.filename(), "normal", false);
                        it = label_fiveTuple_set.find(tmp2);
                        if (it != label_fiveTuple_set.end()) {
                            label_fiveTuple_set.erase(it);
                            sample_statistic["normal"]++;
                            filesystem::rename(pcapfile, filesystem::path(STORE_NORMAL_IN_MAL_DIR + "/" + pcapfile.filename().string()));
                        }else {
                            filesystem::remove(pcapfile);
                        }
                    }
                }
            }
        }
    }
}

void reduceSize_pcap(const filesystem::path &dir_path, string malware_type)
{
    // must run it before "fix_pcap_files" function.
    int index = 0;
    vector<filesystem::path> pcaps;
    get_files(pcaps, dir_path, true);
    sort(pcaps.begin(), pcaps.end(), compare_filename_with_number);
    
     // run tcpdump command per pcap file which size is less than MAX_PCAP_SIZE
    string tmp = filesystem::current_path();
    filesystem::current_path(dir_path);
    vector<pid_t> childs;    
    for (auto pcap_path : pcaps) {
        if (filesystem::file_size(pcap_path) > MAX_PCAP_SIZE * 1024 * 1024) {
            pid_t pid; 
            if ((pid = fork()) == 0)          
                execl("/usr/sbin/tcpdump", "tcpdump", "-r", pcap_path.filename().c_str(),
                    "-w", pcap_path.stem().c_str(), "-C", to_string(MAX_PCAP_SIZE).c_str(), NULL);       
            else             
                childs.push_back(pid); 
        }           
    }
    filesystem::current_path(tmp);
    for (auto &child : childs)
        waitpid(-1, NULL, 0);

    // delete big files
    for (auto ori_pcap_path : pcaps) {
        if (filesystem::file_size(ori_pcap_path) > MAX_PCAP_SIZE * 1024 * 1024) 
            filesystem::remove(ori_pcap_path);
        else
            filesystem::rename(ori_pcap_path, ori_pcap_path.parent_path().string() + "/" + ori_pcap_path.stem().string());
    }
        
    // rename new small files
    get_files(pcaps, dir_path, false);
    sort(pcaps.begin(), pcaps.end());
    ll pcap_file_index = 1;
    for (auto pcap_path : pcaps) {
        filesystem::rename(pcap_path, pcap_path.parent_path().string() + "/" +
                            malware_type + "_" + to_string(pcap_file_index) + ".pcap");
        pcap_file_index++;
    }        

}


int main(void)
{
    // get five-tuple set from label directory
    cout << "------------- update label five-tuple set -------------" << endl;
    vector<filesystem::path> csvFiles;
    set<string> label_fiveTuple_set;    
    map<string, ll> sample_statistic;
    get_files(csvFiles, LABEL_DIR_PATH);
    sort(csvFiles.begin(), csvFiles.end(), compare_filename_with_number);
    for (auto filePath : csvFiles) {
        cout << filePath.filename() << endl;
        update_label_five_tuple_set(label_fiveTuple_set, filePath);
    }


    // // process all pcap files
    vector<filesystem::path> dirs;
    for (auto type : type_order)
        dirs.push_back(filesystem::path(ROOT_DIR_PATH + "/" + type));    
    //get_dirs(dirs, ROOT_DIR_PATH);
    for (auto dir : dirs) {
        // dir variable: it will be "backdoor", "DDOs", "Dos", "ransomware"...
        // run specific malware type
        // cout << "-------------- run specific malware type ----------" << endl;        
        // if (!(dir.stem().compare("normal") == 0))
        //     continue;

        cout << "-------- resize the pcap files ----------" << endl;
        reduceSize_pcap(dir, dir.stem());
        cout << "------------- fix pcap files -------------" << endl;        
        cout << "malware dir path:" << dir << endl;
        fix_pcap_files(dir);
        cout << "------------- pcapng -> pcap procedure -------------" << endl;
        cout << "malware dir path:" << dir << endl;
        pcapng_files_to_pcap_files(dir);
        cout << "------------- split a pcap file to many small files according to 5-tuple -------------" << endl;
        cout << "malware dir path:"  << dir << endl;                
        generate_small_pcaps_according_to_five_tuple(dir, dir.stem(), label_fiveTuple_set, sample_statistic);                        
    }

   
    cout << "--------------------- csv statistic ----------------------" << endl;    
    for (auto &s : stats)   
        cout << s.first << " : " << s.second << endl; 
    
    cout << "------------------small pcap files statistic ----------------------" << endl;
    for (const auto& [malware_type, size] : sample_statistic) 
        cout << malware_type << " : " << size  <<  endl;    


    // show the sessions which don't match in the pcap files.    
    // for (auto entry : label_fiveTuple_set) {        
    //     string malware_type = entry.substr(entry.rfind('_') + 1);                
    //     if (malware_type.compare("backdoor") == 0)
    //         cout << entry << endl;
    // }    
    return 0;
}
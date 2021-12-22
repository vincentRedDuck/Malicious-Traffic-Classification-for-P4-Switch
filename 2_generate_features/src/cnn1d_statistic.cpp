#include <iostream>
#include <string.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <regex>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <math.h> 

#include "SystemUtils.h"  // byteArrayToHexString 
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "PcapFileDevice.h"
#include "GeneralUtils.h"
#include "cnn1d_feature_tool.h"

using namespace std;

map<string, string> pcap_special_type = {{"fixed", "fixed_"}, {"pcap", "p_"}};

// reference: https://medium.com/trabe/loading-binary-files-in-python-that-were-written-using-c-structures-71cb76b7da6b

// ----------------- Hyper Parameter ----------------
const string PCAP_ROOT_DIR = "/home/redduck/Downloads/dataset/script/dataset_eth_header";  // this directory stores all malware-type directories.
const string BIN_FILE_ROOT_DIR = "/home/redduck/Downloads/dataset/script/binfile/cnn1d_first_8_feature";
const int GET_FIRST_PKT_NUMBER = 8;
const int MAX_MEM_SIZE_TO_SAVE_FILE = 1000000;
// --------------------------------------------------

void get_dirs(vector<filesystem::path> &dirs, string dir_path);
void get_files(vector<filesystem::path> &files, string dir_path, bool getPcap=false, string prefix="");
vector<unsigned char> HexToBytes(const std::string& hex);
void one_pcap_handler(vector<Feature_s> &all_session_pkts_statistic, string file_path);


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

void one_pcap_handler(vector<Feature_s> &all_session_pkts_statistic, string file_path)
{
    // specific L4 protocol 
    if(file_path.find("TCP") == string::npos)
        return ;


    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(file_path);    
    // verify that a reader interface was indeed created
    if (reader == NULL) {
        printf("Cannot determine reader for file type\n");
        exit(1);
    }
    // open the reader for reading
    if (!reader->open()) {
        printf("Cannot open input.pcap for reading\n");
        exit(1);
    }
    
    // -------------------handle per packet--------------------
    pcpp::RawPacket rawPacket;
    vector<struct Feature_s> first_pkts(GET_FIRST_PKT_NUMBER); // it would be initialized.
    

    FeatureTool ftool(GET_FIRST_PKT_NUMBER);

    while (ftool.getNowPktCounter() < GET_FIRST_PKT_NUMBER && reader->getNextPacket(rawPacket)) {   
        pcpp::Packet parsedPacket(&rawPacket);        
        pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();     
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();       

        if (ipLayer == NULL || tcpLayer == NULL) {
            cout << "no specific layer!!" << endl;
            exit(0);
        }
        
        ftool.setFirstPktSrcIP(ipLayer);
        ftool.parseTop(rawPacket, ipLayer);
        ftool.parseL3(ipLayer);
        ftool.parseL4(ipLayer, tcpLayer);

        ftool.updateSupport(rawPacket, ipLayer, tcpLayer);                  
    }	
    reader->close();  
        
    all_session_pkts_statistic.insert(all_session_pkts_statistic.end(), ftool.getFeatures().begin(),  ftool.getFeatures().end());        
}

int main()
{
    /*
        get all root directories of malware types
    */
    vector<filesystem::path> mal_rootdirs;
    get_dirs(mal_rootdirs, PCAP_ROOT_DIR);
    sort(mal_rootdirs.begin(), mal_rootdirs.end());
    vector<pid_t> mal_childs; 

    for (auto mal_rootdir : mal_rootdirs) {
        pid_t mal_pid;

        if ((mal_pid = fork()) == 0) {  
            string malware_type = mal_rootdir.stem();        

            // if (malware_type.compare("MITM") != 0) // debug
            //     exit(0);  //debug            
            cout << "malware dir path:" << mal_rootdir << endl;                        

            /*
                get all sub directories in the specific malware root directory
            */
            vector<filesystem::path> mal_subdirs;
            get_dirs(mal_subdirs, mal_rootdir);
            sort(mal_subdirs.begin(), mal_subdirs.end());

            /*
                delete the file that last process created
            */
            filesystem::path parsed_save_file((BIN_FILE_ROOT_DIR + string("/") +
                                                malware_type + string(".bin")).c_str());
            

            ofstream fp;
            fp.open(parsed_save_file.c_str(), ios::out | ios::binary | ios::trunc);
            for (auto mal_subdir : mal_subdirs) {
                cout << "\t" << mal_subdir << endl;
                
                /*
                    get all pcap files in the specific directory and then handle them.
                */
                // if (mal_subdir.stem().string().compare("subdir_MITM_6") != 0) // debug
                //     continue; // debug 

                vector<filesystem::path> session_pcaps;
                vector<Feature_s> all_session_pkts_statistic;            
                get_files(session_pcaps, mal_subdir, true);                
                for (auto session_pcap : session_pcaps) {    
                    // cout << session_pcap << endl; // debug
                    one_pcap_handler(all_session_pkts_statistic, session_pcap);
                    
                    if (sizeof(struct Feature_s) * all_session_pkts_statistic.size() >= MAX_MEM_SIZE_TO_SAVE_FILE) {                        
                        fp.write(reinterpret_cast<const char*>(&all_session_pkts_statistic[0]),
                                                                sizeof(struct Feature_s) * all_session_pkts_statistic.size());                                                                                                
                        vector<Feature_s>().swap(all_session_pkts_statistic);                                    
                    }                                    
                }

                if (all_session_pkts_statistic.size())
                    fp.write(reinterpret_cast<const char*>(&all_session_pkts_statistic[0]),
                                                            sizeof(struct Feature_s) * all_session_pkts_statistic.size());                                
                                
                // cout << "size:" << sizeof(struct Feature_s) << endl; // debug
            }

            fp.close();
            cout << malware_type << " is OK." << endl;
            exit(0);
        } else {            
            mal_childs.push_back(mal_pid);            
        }        
    }   
        
    for (auto &child : mal_childs)
        waitpid(-1, NULL, 0);

    return 0;
}

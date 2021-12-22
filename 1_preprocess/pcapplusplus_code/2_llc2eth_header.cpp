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




#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "PcapFileDevice.h"
#include "GeneralUtils.h"

using namespace std;

typedef unsigned long long int ull;

map<string, string> pcap_special_type = {{"fixed", "fixed_"}, {"pcap", "p_"}};
// Test Path
const string ROOT_DIR_PATH = "/home/redduck/Downloads/dataset/script/test_dataset_label";
// Real Path
// const string ROOT_DIR_PATH = "/home/redduck/Downloads/dataset/Raw_Network_dataset/Network_dataset_pcaps/normal_attack_pcaps"; // this directory stores all malware-type directories.
const int PCAP_NUMBER_PER_PROCESS = 20000;


void llc_to_eth_header(vector<filesystem::path> &pcaps, ull start, ull end);
// void llc_to_eth_header(filesystem::path pcap_path);
// void one_pcap_handler(filesystem::path pcap_path);
void get_dirs(vector<filesystem::path> &dirs, string dir_path);
void get_files(vector<filesystem::path> &files, string dir_path, bool getPcap=false, string prefix="");
bool compare_filename_with_number(filesystem::path p1, filesystem::path p2);


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

void llc_to_eth_header(vector<filesystem::path> &pcaps, ull start, ull end)
{
    for (ull index = start; index <= end; index++)
        system(("tcprewrite --dlt enet --infile " + pcaps[index].string() + " --outfile " + pcaps[index].string()).c_str());
}

// void llc_to_eth_header(filesystem::path pcap_path)
// {
//     system(("tcprewrite --dlt enet --infile " + pcap_path.string() + " --outfile " + pcap_path.string()).c_str());
// }

// void one_pcap_handler(filesystem::path pcap_path) 
// {
//     /*
//         return:
//             true, the eth header is in this pcap
//             false, the eth header isn't in this pcap
//     */
//     // pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcap_path);    
//     // // verify that a reader interface was indeed created
//     // if (reader == NULL) {
//     //     printf("Cannot determine reader for file type\n");
//     //     exit(1);
//     // }

//     // // open the reader for reading
//     // if (!reader->open()) {
//     //     printf("Cannot open input.pcap for reading\n");
//     //     exit(1);
//     // }

//     // // read the first (and only) packet from the file
//     // string session_hex_array = "";
//     // pcpp::RawPacket rawPacket;
//     // bool is_eth_header = true;
//     // while (reader->getNextPacket(rawPacket)) {
//     //     pcpp::Packet parsedPacket(&rawPacket);    
//     //     pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
//     //     if (ethernetLayer == NULL)
//     //         is_eth_header = false;
//     // }    
    
//     // reader->close();
    
//     // if (!is_eth_header)
//     llc_to_eth_header(pcap_path);
// }

int main()
{
    vector<filesystem::path> dirs;
    vector<filesystem::path> small_pcap_files;
    vector<pid_t> mal_dir_childs; 
    

    get_dirs(dirs, ROOT_DIR_PATH);
    for (auto dir : dirs) {
        pid_t root_dir_pid;         
        if ((root_dir_pid = fork()) == 0) {            
            vector<filesystem::path> pcaps;
            cout << "malware dir path:"  << dir << endl;
            
            // stores all pcaps to the pcaps vector
            vector<filesystem::path> small_pacp_dirs;
            get_dirs(small_pacp_dirs, dir);
            sort(small_pacp_dirs.begin(), small_pacp_dirs.end(), compare_filename_with_number);
            for (auto pcap_dir : small_pacp_dirs) {
                vector<filesystem::path> small_pcap_files;
                get_files(small_pcap_files, pcap_dir, true);
                pcaps.insert(pcaps.end(), small_pcap_files.begin(), small_pcap_files.end());               
            }

            // distribute a batch of pcaps each child
            vector<pid_t> batch_pcaps_childs;
            unsigned long long index = 0;
            while(true) {
                pid_t batch_pcaps_pid;
                if(index + (PCAP_NUMBER_PER_PROCESS - 1) > (pcaps.size() - 1)) {
                    if((batch_pcaps_pid = fork()) == 0) {
                        llc_to_eth_header(pcaps, index, pcaps.size() - 1);
                        exit(0);
                    } else {
                        batch_pcaps_childs.push_back(batch_pcaps_pid);
                        break;
                    }                    
                } else {
                    if((batch_pcaps_pid = fork()) == 0) {
                        llc_to_eth_header(pcaps, index, index + ((PCAP_NUMBER_PER_PROCESS - 1)));
                        exit(0);
                    } else {
                        batch_pcaps_childs.push_back(batch_pcaps_pid);                        
                        index += PCAP_NUMBER_PER_PROCESS;                        
                    }
                }
            }

            for (auto &child : batch_pcaps_childs)
                waitpid(-1, NULL, 0);

            cout << dir.stem() << " is OK." << endl;
            exit(0);
        } else {
            mal_dir_childs.push_back(root_dir_pid);
        }
    }
    
    for (auto &child : mal_dir_childs)
        waitpid(-1, NULL, 0);



    // get_dirs(dirs, ROOT_DIR_PATH);
    // for (auto dir : dirs) {
    //     pid_t root_dir_pid;         
    //     if ((root_dir_pid = fork()) == 0) {         
    //         cout << "malware dir path:"  << dir << endl;
    //         vector<filesystem::path> small_pacp_dirs;
    //         vector<pid_t> pcap_dir_childs;
    //         get_dirs(small_pacp_dirs, dir);
    //         sort(small_pacp_dirs.begin(), small_pacp_dirs.end(), compare_filename_with_number);
                        
    //         for (auto pcap_dir : small_pacp_dirs) {
    //             pid_t pcap_dir_pid;
    //             if ((root_dir_pid = fork()) == 0) { 
    //                 cout << "\tpcap dir path:" << pcap_dir << endl;
    //                 get_files(small_pcap_files, pcap_dir, true);
    //                 for (auto pcapfile : small_pcap_files) 
    //                     one_pcap_handler(pcapfile);   
    //                 cout << "\tOK, pcap dir path:" << pcap_dir << endl;
    //                 exit(0);
    //             } else {
    //                 pcap_dir_childs.push_back(pcap_dir_pid);
    //             }                                                      
    //         }

    //         for (auto &child : pcap_dir_childs)
    //             waitpid(-1, NULL, 0);   
    //         cout << "OK, malware dir path:"  << dir << endl; 
    //         exit(0);             
    //     } else {
    //         mal_dir_childs.push_back(root_dir_pid);        
    //     }
    // }
    
    // for (auto &child : mal_dir_childs)
    //     waitpid(-1, NULL, 0); 

    return 0;
}
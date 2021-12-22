#include <sys/types.h>
#include <vector>
#include "IPv4Layer.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"

using namespace std;

struct SessionSupport_s
{    
    // record the last pkt in the same session
    //--------------- support top statistic -----------
    bool flow_is_first_pkt[2]; //used for flow IAT feature
    pcpp::IPAddress forward_src_ip;
    unsigned int current_session_pkt_index; //because it start from 0
    timespec session_last_pkt_arrival_time;
    timespec flow_last_pkt_arrival_time[2];
    double session_IAT_total;
    double session_IAT_max;
    double session_IAT_min;
    vector<double> vec_session_IAT;
    double flow_IAT_min[2];
    double flow_IAT_max[2];
    double flow_IAT_total[2];
    vector<vector<double> > vec_flow_IAT;    
    int flow_pkt_min_size[2];
    int flow_pkt_max_size[2];
    unsigned int flow_pkt_counter[2];  
    vector<vector<int> > vec_flow_pkt_size;
    //-------------- support L3 statistic ------------
    unsigned int session_ttl_counter = 0;
    //-------------- support L4 statistic ------------    
    int flow_window_min_size[2];
    int flow_window_max_size[2];
    unsigned int flow_pkt_size_total[2]; 
    unsigned int flow_window_size_total[2];
    vector<vector<int> > vec_flow_window_size;
    unsigned int session_ack_counter;
    unsigned int session_syn_counter;
    unsigned int session_psh_counter;
    unsigned int session_rst_counter;
    unsigned int session_fin_counter;
};

struct Feature_s
{
    /*  
        flow direction: 
            index 0: forward path
            index 1: backward path      
    */   
    // ---- counters (top) ----    
    float flow_pkt_mean_size[2]; // check OK (0)
    unsigned int flow_pkt_total_size[2];   // check OK (2)
    float flow_pkt_variance_size[2]; // check OK (4)
    int flow_pkt_min_size[2]; // check OK (6)
    int flow_pkt_max_size[2]; // check OK (8)

    double session_IAT; // check OK (10)
    double session_IAT_mean; // check OK (11)
    double session_IAT_variance; // check OK (12)
    double session_IAT_max; // check OK (13)
    double session_IAT_min; // check OK (14)
    double flow_IAT_mean[2]; // check OK (15)
    double flow_IAT_total[2];  // check OK (17)
    double flow_IAT_variance[2]; // check OK (19)
    double flow_IAT_max[2]; // check OK (21)
    double flow_IAT_min[2]; // check OK (23)
    // ---- L3 feature ----
    float session_ttl_mean; // check OK (25)
    // ---- L4 feature ----
    float flow_window_mean_size[2]; // check OK (26)
    unsigned int flow_window_total_size[2]; // check OK (28)
    float flow_window_variance_size[2]; // check OK (30)
    int flow_window_min_size[2]; // check OK (32)
    int flow_window_max_size[2]; // check OK (34)
    unsigned int session_ack_total_size; // check OK (36)
    unsigned int session_syn_total_size; // check OK (37)
    unsigned int session_psh_total_size; // check OK (38)
    unsigned int session_rst_total_size; // check OK (39)
    unsigned int session_fin_total_size; // check OK (40)
};

class FeatureTool
{
    /*
        index of each array:
            0: src. ip in first pkt
            1: dst. ip in first pkt
    */
    SessionSupport_s session_support;    
    vector<Feature_s> features;  //be used for 1d-cnn input
    //------- top --------
    unsigned int pkt_counter;
    //------- L4 --------
    unsigned int ack_counter;
    unsigned int syn_counter;
    unsigned int psh_counter;
    unsigned int rst_counter;
    unsigned int fin_counter; 
    double getIATBetweenPkts(timespec last_pkt_arrival_time, pcpp::RawPacket &rawPacket);
    
    void featureSessionIAT(int f_number, pcpp::RawPacket &rawPacket);
    
    void featureSessionIATMean(int f_number, pcpp::RawPacket &rawPacket);
    void featureSessionIATVariance(int f_number, pcpp::RawPacket &rawPacket);
    void featureSessionIATMax(int f_number, pcpp::RawPacket &rawPacket);
    void featureSessionIATMin(int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowIATTotal(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowIATMean(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowIATMax(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowIATMin(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowIATVariance(int role, int f_number, pcpp::RawPacket &rawPacket);

    void featureSessionTTLMean(int f_number, pcpp::IPv4Layer *ipLayer);    
    void featureFlowPktMeanSize(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowPktTotalSize(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowPktVarianceSize(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowPktMinSize(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowPktMaxSize(int role, int f_number, pcpp::RawPacket &rawPacket);
    void featureFlowWindowMeanSize(int role, int f_number, pcpp::TcpLayer *tcpLayer);
    void featureFlowWindowTotalSize(int role, int f_number, pcpp::TcpLayer *tcpLayer);
    void featureFlowWindowVarianceSize(int role, int f_number, pcpp::TcpLayer *tcpLayer);
    void featureFlowWindowMinSize(int role, int f_number, pcpp::TcpLayer *tcpLayer);
    void featureFlowWindowMaxSize(int role, int f_number, pcpp::TcpLayer *tcpLayer);    
    void featureL4Flag(int role, int f_number, pcpp::TcpLayer *tcpLayer);
public:
    FeatureTool(int first_pkt_number);    
    vector<Feature_s>& getFeatures();
    int getNowPktCounter();    
    void parseTop(pcpp::RawPacket &rawPacket, pcpp::IPv4Layer* ipLayer);
    void parseL3(pcpp::IPv4Layer* ipLayer);
    void parseL4(pcpp::IPv4Layer* ipLayer, pcpp::TcpLayer* tcpLayer);  
    void updateSupport(pcpp::RawPacket &rawPacket, pcpp::IPv4Layer* ipLayer, pcpp::TcpLayer* tcpLayer);
    void setFirstPktSrcIP(pcpp::IPv4Layer* ipLayer);
};
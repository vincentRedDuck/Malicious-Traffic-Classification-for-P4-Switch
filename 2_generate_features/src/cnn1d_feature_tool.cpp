#include <math.h>
#include <iostream>

#include "cnn1d_feature_tool.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"  // byteArrayToHexString

FeatureTool::FeatureTool(int first_pkt_number) : session_support()
{
    for (auto &min_pkt_size : session_support.flow_pkt_min_size) min_pkt_size = -1;
    for (auto &max_pkt_size : session_support.flow_pkt_max_size) max_pkt_size = -1;        
    for (auto &min_window_size : session_support.flow_window_min_size) min_window_size = -1;
    for (auto &max_window_size : session_support.flow_window_max_size) max_window_size = -1;    
    for (auto &is_first_pkt : session_support.flow_is_first_pkt) is_first_pkt = true;
    for (auto &max_IAT : session_support.flow_IAT_max) max_IAT = -1;
    for (auto &min_IAT : session_support.flow_IAT_min) min_IAT = -1;
    this->session_support.session_IAT_max = -1;
    this->session_support.session_IAT_min = -1;
    this->features.resize(first_pkt_number);
    this->session_support.vec_flow_IAT.push_back(vector<double>());
    this->session_support.vec_flow_IAT.push_back(vector<double>());
    this->session_support.vec_flow_pkt_size.push_back(vector<int>());
    this->session_support.vec_flow_pkt_size.push_back(vector<int>());
    this->session_support.vec_flow_window_size.push_back(vector<int>());
    this->session_support.vec_flow_window_size.push_back(vector<int>());    
}


//parse order: top -> L3 -> L4...
void FeatureTool::parseTop(pcpp::RawPacket &rawPacket, pcpp::IPv4Layer* ipLayer)
{
    int role = (this->session_support.forward_src_ip != ipLayer->getSrcIPAddress());

    this->featureSessionIAT(this->session_support.current_session_pkt_index, rawPacket);
    this->featureSessionIATMean(this->session_support.current_session_pkt_index, rawPacket);    
    this->featureSessionIATMax(this->session_support.current_session_pkt_index, rawPacket);
    this->featureSessionIATMin(this->session_support.current_session_pkt_index, rawPacket);
    this->featureSessionIATVariance(this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowIATTotal(role, this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowIATMean(role, this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowIATMax(role, this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowIATMin(role, this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowIATVariance(role, this->session_support.current_session_pkt_index, rawPacket);

    this->featureFlowPktTotalSize(role, this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowPktMeanSize(role, this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowPktMinSize(role, this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowPktMaxSize(role, this->session_support.current_session_pkt_index, rawPacket);
    this->featureFlowPktVarianceSize(role, this->session_support.current_session_pkt_index, rawPacket);

}

void FeatureTool::parseL3(pcpp::IPv4Layer* ipLayer)
{
   this->featureSessionTTLMean(this->session_support.current_session_pkt_index, ipLayer);
}

void FeatureTool::parseL4(pcpp::IPv4Layer* ipLayer, pcpp::TcpLayer* tcpLayer)
{
    // 5-tuple can decide src-dst path.
    /*
        the value of role var.
            0: src. of the forward path
            1: dst. of the forward path
    */
    
    int role = (this->session_support.forward_src_ip != ipLayer->getSrcIPAddress());    
    this->featureFlowWindowMeanSize(role, this->session_support.current_session_pkt_index, tcpLayer);
    this->featureFlowWindowTotalSize(role, this->session_support.current_session_pkt_index, tcpLayer);
    this->featureFlowWindowVarianceSize(role, this->session_support.current_session_pkt_index, tcpLayer);
    this->featureFlowWindowMinSize(role, this->session_support.current_session_pkt_index, tcpLayer);
    this->featureFlowWindowMaxSize(role, this->session_support.current_session_pkt_index, tcpLayer);   
    this->featureL4Flag(role, this->session_support.current_session_pkt_index, tcpLayer);
}

void FeatureTool::setFirstPktSrcIP(pcpp::IPv4Layer* ipLayer)
{
    if (this->session_support.current_session_pkt_index == 0)
        this->session_support.forward_src_ip = ipLayer->getSrcIPAddress();
}

void FeatureTool::updateSupport(pcpp::RawPacket &rawPacket, pcpp::IPv4Layer* ipLayer, pcpp::TcpLayer* tcpLayer)
{         
    int role = (this->session_support.forward_src_ip != ipLayer->getSrcIPAddress());
    int f_number = this->session_support.current_session_pkt_index;
    
    // ---- counters (top) ----                
    // ordered instruction
    if(!this->session_support.flow_is_first_pkt[role]) {  
        this->session_support.vec_flow_IAT[role].push_back(
            this->getIATBetweenPkts(this->session_support.flow_last_pkt_arrival_time[role], rawPacket));
    }
    if(this->session_support.current_session_pkt_index != 0) {        
        this->session_support.session_IAT_total += this->getIATBetweenPkts(
            this->session_support.session_last_pkt_arrival_time, rawPacket);        
    }
    if(this->session_support.current_session_pkt_index != 0) {        
        this->session_support.vec_session_IAT.push_back(
            this->getIATBetweenPkts(this->session_support.session_last_pkt_arrival_time, rawPacket));
    }
    // non-ordered instruction
    this->session_support.current_session_pkt_index++;
    this->session_support.session_last_pkt_arrival_time = rawPacket.getPacketTimeStamp();       
    this->session_support.flow_last_pkt_arrival_time[role] = rawPacket.getPacketTimeStamp();
    this->session_support.session_IAT_max = this->features[f_number].session_IAT_max;
    this->session_support.session_IAT_min = this->features[f_number].session_IAT_min;
    this->session_support.flow_IAT_total[role] = this->features[f_number].flow_IAT_total[role];
    this->session_support.flow_IAT_max[role] = this->features[f_number].flow_IAT_max[role];
    this->session_support.flow_IAT_min[role] = this->features[f_number].flow_IAT_min[role];
    this->session_support.flow_is_first_pkt[role] = false;
    this->session_support.vec_flow_pkt_size[role].push_back(rawPacket.getRawDataLen());
    
    
    // ---- L3 feature ----
    this->session_support.session_ttl_counter += ipLayer->getIPv4Header()->timeToLive;
    
    // ---- L4 feature ----
    this->session_support.flow_pkt_counter[role]++;
    this->session_support.flow_pkt_size_total[role] += rawPacket.getRawDataLen();
    this->session_support.flow_window_size_total[role] += (int)pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize);     
    this->session_support.flow_pkt_min_size[role] = this->features[f_number].flow_pkt_min_size[role];
    this->session_support.flow_pkt_max_size[role] = this->features[f_number].flow_pkt_max_size[role];
    this->session_support.flow_window_min_size[role] = this->features[f_number].flow_window_min_size[role];
    this->session_support.flow_window_max_size[role] = this->features[f_number].flow_window_max_size[role];
    this->session_support.vec_flow_window_size[role].push_back((int)pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize));
    this->session_support.session_ack_counter += tcpLayer->getTcpHeader()->ackFlag;
    this->session_support.session_syn_counter += tcpLayer->getTcpHeader()->synFlag;
    this->session_support.session_psh_counter += tcpLayer->getTcpHeader()->pshFlag;
    this->session_support.session_rst_counter += tcpLayer->getTcpHeader()->rstFlag;
    this->session_support.session_fin_counter += tcpLayer->getTcpHeader()->finFlag;
}

vector<Feature_s>& FeatureTool::getFeatures()
{
    return this->features;
}

int FeatureTool::getNowPktCounter()
{
    return this->session_support.current_session_pkt_index;
}

double FeatureTool::getIATBetweenPkts(timespec last_pkt_arrival_time, pcpp::RawPacket &rawPacket)
{
    double sec = rawPacket.getPacketTimeStamp().tv_sec - last_pkt_arrival_time.tv_sec;
    double nsec = rawPacket.getPacketTimeStamp().tv_nsec - last_pkt_arrival_time.tv_nsec;
    return (sec + nsec * pow(10,-9));
}

// ------------------------ feature ------------------------
void FeatureTool::featureSessionIAT(int f_number, pcpp::RawPacket &rawPacket)
{
    //interval arrival time
    if (this->session_support.current_session_pkt_index != 0) {
        this->features[f_number].session_IAT = 
            getIATBetweenPkts(this->session_support.session_last_pkt_arrival_time, rawPacket);            
    }
}

void FeatureTool::featureSessionIATMean(int f_number, pcpp::RawPacket &rawPacket)
{
    /*
        meta data:
            this->session_support.current_session_pkt_index
            this->session_support.session_IAT_total            
            this->session_support.session_last_pkt_arrival_time
    */
    if (this->session_support.current_session_pkt_index != 0) {              
        double IAT_total = this->session_support.session_IAT_total +
            this->getIATBetweenPkts(this->session_support.session_last_pkt_arrival_time, rawPacket);
        unsigned int pkt_interval_space_number = this->session_support.current_session_pkt_index;
        this->features[f_number].session_IAT_mean = IAT_total / (double)pkt_interval_space_number;
        
    }
}

void FeatureTool::featureSessionIATVariance(int f_number, pcpp::RawPacket &rawPacket)
{
    /*
        meta data:
            this->session_support.current_session_pkt_index
            this->session_support.session_last_pkt_arrival_time
            this->session_support.vec_session_IAT
    */
    if (this->session_support.current_session_pkt_index != 0) {
        unsigned int pkt_interval_space_number = this->session_support.current_session_pkt_index;
        double new_IAT = this->getIATBetweenPkts(this->session_support.session_last_pkt_arrival_time, rawPacket);

        double total_IAT = 0;
        for (auto IAT_element : this->session_support.vec_session_IAT)
            total_IAT += IAT_element;   
        total_IAT += new_IAT;
        double IAT_mean = total_IAT / (float)(pkt_interval_space_number);

        double variance = 0;
        for (auto IAT_element : this->session_support.vec_session_IAT)
            variance += pow(IAT_element - IAT_mean, 2);
        variance += pow(new_IAT - IAT_mean, 2);        
        variance /= (float)pkt_interval_space_number;
        // variance = sqrt(variance);
        this->features[f_number].session_IAT_variance = variance;
    }
}

void FeatureTool::featureSessionIATMax(int f_number, pcpp::RawPacket &rawPacket)
{   
    /*
        meta data:            
            this->session_support.current_session_pkt_index            
            this->session_support.session_last_pkt_arrival_time
            this->session_support.session_IAT_max
    */
    if (this->session_support.current_session_pkt_index != 0) {
        double last_max_IAT = this->session_support.session_IAT_max;
        double new_IAT = this->getIATBetweenPkts(this->session_support.session_last_pkt_arrival_time, rawPacket);
        if (new_IAT > last_max_IAT | last_max_IAT == -1)
            this->features[f_number].session_IAT_max = new_IAT;  
        else
            this->features[f_number].session_IAT_max = last_max_IAT;  
    } else {
        // assign -1 to this feature
        this->features[f_number].session_IAT_max = this->session_support.session_IAT_max;  
    }
}

void FeatureTool::featureSessionIATMin(int f_number, pcpp::RawPacket &rawPacket)
{   
    /*
        meta data:            
            this->session_support.current_session_pkt_index            
            this->session_support.session_last_pkt_arrival_time
            this->session_support.session_IAT_min
    */
    if (this->session_support.current_session_pkt_index != 0) {
        double last_min_IAT = this->session_support.session_IAT_min;
        double new_IAT = this->getIATBetweenPkts(this->session_support.session_last_pkt_arrival_time, rawPacket);
        if (new_IAT < last_min_IAT | last_min_IAT == -1)
            this->features[f_number].session_IAT_min = new_IAT;  
        else
            this->features[f_number].session_IAT_min = last_min_IAT;  
    } else {
        // assign -1 to this feature
        this->features[f_number].session_IAT_min = this->session_support.session_IAT_min;  
    }
}

void FeatureTool::featureFlowIATTotal(int role, int f_number, pcpp::RawPacket &rawPacket)
{        
    //target flow
    if (!this->session_support.flow_is_first_pkt[role]) {
        this->features[f_number].flow_IAT_total[role] = this->session_support.flow_IAT_total[role]
            + this->getIATBetweenPkts(this->session_support.flow_last_pkt_arrival_time[role], rawPacket);
    }

    //other flow
    if (f_number != 0)
        this->features[f_number].flow_IAT_total[!(role)] = this->features[f_number - 1].flow_IAT_total[!(role)];    
}

void FeatureTool::featureFlowIATMean(int role, int f_number, pcpp::RawPacket &rawPacket)
{    
    //target flow
    if (!this->session_support.flow_is_first_pkt[role]) {
        double total = this->session_support.flow_IAT_total[role] 
            + this->getIATBetweenPkts(this->session_support.flow_last_pkt_arrival_time[role], rawPacket);
        unsigned int pkt_interval_space_number = this->session_support.flow_pkt_counter[role];
        this->features[f_number].flow_IAT_mean[role] = total / (float)(pkt_interval_space_number);
    }

    //other flow
    if (f_number != 0)
        this->features[f_number].flow_IAT_mean[!(role)] = this->features[f_number - 1].flow_IAT_mean[!(role)];    
}

void FeatureTool::featureFlowIATMax(int role, int f_number, pcpp::RawPacket &rawPacket)
{    
    //target flow
    if (!this->session_support.flow_is_first_pkt[role]) {
        double last_max_IAT = this->session_support.flow_IAT_max[role];
        double new_IAT = this->getIATBetweenPkts(this->session_support.flow_last_pkt_arrival_time[role], rawPacket);        
        if (new_IAT > last_max_IAT | last_max_IAT == -1)
            this->features[f_number].flow_IAT_max[role] = new_IAT;
        else
            this->features[f_number].flow_IAT_max[role] = last_max_IAT;        
    } else {
        // assign -1 to this feature
        this->features[f_number].flow_IAT_max[role] = this->session_support.flow_IAT_max[role];
    }

    //other flow
    if (!this->session_support.flow_is_first_pkt[role]) {
        this->features[f_number].flow_IAT_max[!(role)] = this->features[f_number - 1].flow_IAT_max[!(role)];    
    } else {
        // assign -1 to this feature
        this->features[f_number].flow_IAT_max[!(role)] = this->session_support.flow_IAT_max[!(role)];
    }
}

void FeatureTool::featureFlowIATMin(int role, int f_number, pcpp::RawPacket &rawPacket)
{    
    //target flow
    if (!this->session_support.flow_is_first_pkt[role]) {
        double last_min_IAT = this->session_support.flow_IAT_min[role];
        double new_IAT = this->getIATBetweenPkts(this->session_support.flow_last_pkt_arrival_time[role], rawPacket);        
        if (new_IAT < last_min_IAT | last_min_IAT == -1)
            this->features[f_number].flow_IAT_min[role] = new_IAT;
        else
            this->features[f_number].flow_IAT_min[role] = last_min_IAT;        
    } else {
        // assign -1 to this feature
        this->features[f_number].flow_IAT_min[role] = this->session_support.flow_IAT_min[role];
    }

    //other flow
    if (!this->session_support.flow_is_first_pkt[role]) {
        this->features[f_number].flow_IAT_min[!(role)] = this->features[f_number - 1].flow_IAT_min[!(role)];    
    } else {
        // assign -1 to this feature
        this->features[f_number].flow_IAT_min[!(role)] = this->session_support.flow_IAT_min[!(role)];
    }
}

void FeatureTool::featureFlowIATVariance(int role, int f_number, pcpp::RawPacket &rawPacket)
{
    // target flow
    if (!this->session_support.flow_is_first_pkt[role]) {
        
        unsigned int pkt_interval_space_number = this->session_support.flow_pkt_counter[role];
        double new_IAT = this->getIATBetweenPkts(this->session_support.flow_last_pkt_arrival_time[role], rawPacket);

        double total_IAT = 0;
        for (auto IAT_element : this->session_support.vec_flow_IAT[role])
            total_IAT += IAT_element;            
        total_IAT += new_IAT;
        double IAT_mean = total_IAT / (float)(pkt_interval_space_number);

        double variance = 0;
        for (auto IAT_element : this->session_support.vec_flow_IAT[role])
            variance += pow(IAT_element - IAT_mean, 2);
        variance += pow(new_IAT - IAT_mean, 2);        
        variance /= (float)pkt_interval_space_number;
        // variance = sqrt(variance);
        this->features[f_number].flow_IAT_variance[role] = variance;

        
    }

    //other flow
    if(f_number != 0)
        this->features[f_number].flow_IAT_variance[!(role)] = this->features[f_number - 1].flow_IAT_variance[!(role)];
}

void FeatureTool::featureSessionTTLMean(int f_number, pcpp::IPv4Layer *ipLayer)
{
    unsigned int ttl_counter = this->session_support.session_ttl_counter 
                                + ipLayer->getIPv4Header()->timeToLive;
    unsigned int pkt_number = this->session_support.current_session_pkt_index + 1;                                 
    this->features[f_number].session_ttl_mean = (float)(ttl_counter) / (float)(pkt_number);
}

void FeatureTool::featureFlowPktMeanSize(int role, int f_number, pcpp::RawPacket &rawPacket)
{
    //target flow
    unsigned int total_pkt_size = this->session_support.flow_pkt_size_total[role]
                                        + rawPacket.getRawDataLen();
    unsigned int pkt_number = this->session_support.flow_pkt_counter[role] + 1;                                        
    this->features[f_number].flow_pkt_mean_size[role] = (float)total_pkt_size / (float)(pkt_number);                                                        
    
    //other flow
    if (f_number != 0)
        this->features[f_number].flow_pkt_mean_size[!(role)] = this->features[f_number - 1].flow_pkt_mean_size[!(role)];
}

void FeatureTool::featureFlowPktTotalSize(int role, int f_number, pcpp::RawPacket &rawPacket)
{
    //target flow
    this->features[f_number].flow_pkt_total_size[role] += this->session_support.flow_pkt_size_total[role]
                                                           +  rawPacket.getRawDataLen();    
    //other flow
    if (f_number != 0)
        this->features[f_number].flow_pkt_total_size[!(role)] = this->features[f_number - 1].flow_pkt_total_size[!(role)];
}

void FeatureTool::featureFlowPktVarianceSize(int role, int f_number, pcpp::RawPacket &rawPacket)
{
    // target flow
    unsigned int totol_pkt_size = this->session_support.flow_pkt_size_total[role]
                            +  rawPacket.getRawDataLen();
    double avg_pkt_size = (double)totol_pkt_size / (double)(this->session_support.flow_pkt_counter[role] + 1);
    
    double variance = 0;
    for (auto pkt_size : this->session_support.vec_flow_pkt_size[role])
        variance += pow(pkt_size - avg_pkt_size, 2);
    variance += pow(rawPacket.getRawDataLen() - avg_pkt_size, 2);
    variance /= (float)(this->session_support.flow_pkt_counter[role] + 1);
    // variance = sqrt(variance);
    this->features[f_number].flow_pkt_variance_size[role] = variance;    

    //other flow
    if(f_number != 0)
        this->features[f_number].flow_pkt_variance_size[!(role)] = this->features[f_number - 1].flow_pkt_variance_size[!(role)];
}

void FeatureTool::featureFlowPktMinSize(int role, int f_number, pcpp::RawPacket &rawPacket)
{    
    //target flow
    int last_feature = this->session_support.flow_pkt_min_size[role];
    
    if (last_feature > rawPacket.getRawDataLen() | last_feature == -1) {                
        this->features[f_number].flow_pkt_min_size[role] = rawPacket.getRawDataLen();
    } else {
        this->features[f_number].flow_pkt_min_size[role] = last_feature;
    }

    //other flow    
    this->features[f_number].flow_pkt_min_size[!(role)] = this->session_support.flow_pkt_min_size[!(role)];
}

void FeatureTool::featureFlowPktMaxSize(int role, int f_number, pcpp::RawPacket &rawPacket)
{    
    // target flow
    int last_feature = this->session_support.flow_pkt_max_size[role];
    if (last_feature < rawPacket.getRawDataLen() | last_feature == -1)        
        this->features[f_number].flow_pkt_max_size[role] = rawPacket.getRawDataLen();
    else
        this->features[f_number].flow_pkt_max_size[role] = last_feature; 

    // other flow    
    this->features[f_number].flow_pkt_max_size[!(role)] = this->session_support.flow_pkt_max_size[!(role)];
}

void FeatureTool::featureFlowWindowMeanSize(int role, int f_number, pcpp::TcpLayer *tcpLayer)
{
    //target flow
    unsigned int total_window_size = this->session_support.flow_window_size_total[role]
                                        + (int)pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize);
    unsigned int pkt_number = session_support.flow_pkt_counter[role] + 1;                                        
    this->features[f_number].flow_window_mean_size[role] = (float)total_window_size / (float)(pkt_number);                                                        
    
    //other flow
    if (f_number != 0)
        this->features[f_number].flow_window_mean_size[!(role)] = this->features[f_number - 1].flow_window_mean_size[!(role)];
}

void FeatureTool::featureFlowWindowTotalSize(int role, int f_number, pcpp::TcpLayer *tcpLayer)
{
    //target flow
    this->features[f_number].flow_window_total_size[role] += this->session_support.flow_window_size_total[role]
                                                           +  (int)pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize);    
    //other flow
    if (f_number != 0)
        this->features[f_number].flow_window_total_size[!(role)] = this->features[f_number - 1].flow_window_total_size[!(role)];
}

void FeatureTool::featureFlowWindowVarianceSize(int role, int f_number, pcpp::TcpLayer *tcpLayer)
{
    //target flow
    unsigned int totol_window_size = this->session_support.flow_window_size_total[role]
                                       +  (int)pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize);    
    double avg_window_size = (double)totol_window_size / (double)(this->session_support.flow_pkt_counter[role] + 1);
    double variance = 0;
    for (auto window_size : this->session_support.vec_flow_window_size[role])
        variance += pow(window_size - avg_window_size, 2);
    variance += pow((int)pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) - avg_window_size, 2);
    variance /= (float)(this->session_support.flow_pkt_counter[role] + 1);
    // variance = sqrt(variance);    
    this->features[f_number].flow_window_variance_size[role] = variance;    

    //other flow
    if(f_number != 0)
        this->features[f_number].flow_window_variance_size[!(role)] = this->features[f_number - 1].flow_window_variance_size[!(role)];
}

void FeatureTool::featureFlowWindowMinSize(int role, int f_number, pcpp::TcpLayer *tcpLayer)
{    
    //target flow
    int last_feature = this->session_support.flow_window_min_size[role];
    if (last_feature > tcpLayer->getTcpHeader()->windowSize | last_feature == -1)
        this->features[f_number].flow_window_min_size[role] = (int)pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize);
    else
        this->features[f_number].flow_window_min_size[role] = last_feature;            
    
    //other flow   
    this->features[f_number].flow_window_min_size[!(role)] = this->session_support.flow_window_min_size[!(role)];
}

void FeatureTool::featureFlowWindowMaxSize(int role, int f_number, pcpp::TcpLayer *tcpLayer)
{    
    //target flow
    int last_feature = this->session_support.flow_window_max_size[role];
    if (last_feature < tcpLayer->getTcpHeader()->windowSize | last_feature == -1)
        this->features[f_number].flow_window_max_size[role] = (int)pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize);
    else
        this->features[f_number].flow_window_max_size[role] = last_feature;    

    //other flow   
    this->features[f_number].flow_window_max_size[!(role)] = this->session_support.flow_window_max_size[!(role)];        
}

void FeatureTool::featureL4Flag(int role, int f_number, pcpp::TcpLayer *tcpLayer)
{
    this->features[f_number].session_ack_total_size = this->session_support.session_ack_counter + tcpLayer->getTcpHeader()->ackFlag;
    this->features[f_number].session_syn_total_size = this->session_support.session_syn_counter + tcpLayer->getTcpHeader()->synFlag;
    this->features[f_number].session_psh_total_size = this->session_support.session_psh_counter + tcpLayer->getTcpHeader()->pshFlag;
    this->features[f_number].session_rst_total_size = this->session_support.session_rst_counter + tcpLayer->getTcpHeader()->rstFlag;
    this->features[f_number].session_fin_total_size = this->session_support.session_fin_counter + tcpLayer->getTcpHeader()->finFlag;
}


#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/gnuplot.h"
#include <string>
#include <vector>
#include <random>
#include <openssl/sha.h>
#include <miracl.h>
#include <mirdef.h>

using namespace ns3;


struct Divisor {
    std::vector<uint8_t> data;
    Divisor() : data(80) {}
};

struct FiniteFieldElement {
    uint64_t value;
    FiniteFieldElement(uint64_t v = 0) : value(v % (1ULL << 80)) {}
};


class HECCLibrary {
public:
    static Divisor Multiply(Divisor P, FiniteFieldElement scalar) {
        Divisor result;


        return result;
    }
    static Divisor Add(Divisor A, Divisor B) {
        Divisor result;

        return result;
    }
};


std::vector<uint8_t> Hash(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    SHA256(input.data(), input.size(), output.data());
    return output;
}


struct SigncryptionParams {
    Divisor P;
    FiniteFieldElement mu_PKGC;
    Divisor gamma_PKGC;
    Divisor sigma_EVTG;
    FiniteFieldElement lambda_EVTG;
    std::string Drone_RID;
    FiniteFieldElement eta_Drone;
    Divisor beta_Drone;
    FiniteFieldElement PK_Drone;
};


std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    return Encrypt(data, key);
}


struct SigncryptionTuple {
    FiniteFieldElement S_Drone;
    Divisor chi_Drone;
    std::vector<uint8_t> C_Drone;
};

SigncryptionTuple HeterogeneousSigncryption(const std::vector<uint8_t>& message, SigncryptionParams& params) {
    SigncryptionTuple result;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1, (1ULL << 80) - 1);


    FiniteFieldElement rho_Drone(dist(gen));


    result.chi_Drone = HECCLibrary::Multiply(params.P, rho_Drone);


    Divisor K = HECCLibrary::Multiply(params.sigma_EVTG, rho_Drone);


    std::vector<uint8_t> K_data(K.data);
    std::vector<uint8_t> chi_data(result.chi_Drone.data);
    K_data.insert(K_data.end(), chi_data.begin(), chi_data.end());
    std::vector<uint8_t> k = Hash(K_data);


    std::vector<uint8_t> EID_data(params.Drone_RID.begin(), params.Drone_RID.end());
    std::vector<uint8_t> message_with_EID = message;
    message_with_EID.insert(message_with_EID.end(), EID_data.begin(), EID_data.end());
    result.C_Drone = Encrypt(message_with_EID, k);


    std::vector<uint8_t> pi_2_input = message;
    pi_2_input.insert(pi_2_input.end(), chi_data.begin(), chi_data.end());
    pi_2_input.insert(pi_2_input.end(), EID_data.begin(), EID_data.end());
    std::vector<uint8_t> pi_2 = Hash(pi_2_input);


    FiniteFieldElement pi_2_scalar = FiniteFieldElement(*reinterpret_cast<uint64_t*>(pi_2.data()));
    result.S_Drone = FiniteFieldElement(rho_Drone.value + pi_2_scalar.value * params.PK_Drone.value);

    return result;
}

std::vector<uint8_t> HeterogeneousUnsigncryption(const SigncryptionTuple& tuple, SigncryptionParams& params) {

    Divisor K = HECCLibrary::Multiply(tuple.chi_Drone, params.lambda_EVTG);


    std::vector<uint8_t> K_data(K.data);
    std::vector<uint8_t> chi_data(tuple.chi_Drone.data);
    K_data.insert(K_data.end(), chi_data.begin(), chi_data.end());
    std::vector<uint8_t> k = Hash(K_data);


    std::vector<uint8_t> decrypted = Decrypt(tuple.C_Drone, k);


    std::string EID(params.Drone_RID);
    size_t EID_size = EID.size();
    if (decrypted.size() < EID_size) {
        NS_LOG_UNCOND("Decryption failed: Invalid data size");
        return {};
    }
    std::vector<uint8_t> message(decrypted.begin(), decrypted.end() - EID_size);
    std::string received_EID(decrypted.end() - EID_size, decrypted.end());
    if (received_EID != EID) {
        NS_LOG_UNCOND("Decryption failed: Invalid EID");
        return {};
    }


    std::vector<uint8_t> pi_2_input = message;
    pi_2_input.insert(pi_2_input.end(), chi_data.begin(), chi_data.end());
    pi_2_input.insert(pi_2_input.end(), EID.begin(), EID.end());
    std::vector<uint8_t> pi_2 = Hash(pi_2_input);
    FiniteFieldElement pi_2_scalar = FiniteFieldElement(*reinterpret_cast<uint64_t*>(pi_2.data()));


    std::vector<uint8_t> pi_1_input(params.beta_Drone.data);
    pi_1_input.insert(pi_1_input.end(), EID.begin(), EID.end());
    std::vector<uint8_t> pi_1 = Hash(pi_1_input);
    FiniteFieldElement pi_1_scalar = FiniteFieldElement(*reinterpret_cast<uint64_t*>(pi_1.data()));


    Divisor left = HECCLibrary::Multiply(params.P, tuple.S_Drone);
    Divisor right_term1 = tuple.chi_Drone;
    Divisor right_term2 = HECCLibrary::Multiply(params.beta_Drone, pi_2_scalar);
    Divisor right_term3 = HECCLibrary::Multiply(params.gamma_PKGC, FiniteFieldElement(pi_1_scalar.value * pi_2_scalar.value));
    Divisor right = HECCLibrary::Add(right_term1, HECCLibrary::Add(right_term2, right_term3));


    bool verified = left.data == right.data;
    if (!verified) {
        NS_LOG_UNCOND("Signature verification failed");
        return {};
    }

    return message;
}

NS_LOG_COMPONENT_DEFINE("MultiDroneSigncryption");

class SigncryptionUdpSender : public Application {
public:
    SigncryptionUdpSender() : m_socket(0), m_peer(), m_packetSize(0), m_dataRate(0), 
                             m_sendEvent(), m_running(false), m_packetsSent(0) {}
    
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("SigncryptionUdpSender")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<SigncryptionUdpSender>();
        return tid;
    }

    void Setup(Ptr<Socket> socket, Address address, uint32_t packetSize, DataRate dataRate, SigncryptionParams params) {
        m_socket = socket;
        m_peer = address;
        m_packetSize = packetSize;
        m_dataRate = dataRate;
        m_params = params;
    }

private:
    void StartApplication() override {
        m_running = true;
        m_packetsSent = 0;
        m_socket->Bind();
        m_socket->Connect(m_peer);
        ScheduleNextTx();
    }

    void StopApplication() override {
        m_running = false;
        CancelEvents();
        if (m_socket) {
            m_socket->Close();
        }
    }

    void ScheduleNextTx() {
        if (m_running) {
            Time nextTime(Seconds(m_packetSize * 8.0 / static_cast<double>(m_dataRate.GetBitRate())));
            m_sendEvent = Simulator::Schedule(nextTime, &SigncryptionUdpSender::SendPacket, this);
        }
    }

    void SendPacket() {
        std::vector<uint8_t> data(m_packetSize);
        for (uint32_t i = 0; i < m_packetSize; ++i) {
            data[i] = static_cast<uint8_t>(i % 256);
        }
        SigncryptionTuple tuple = HeterogeneousSigncryption(data, m_params);
        

        std::vector<uint8_t> packetData;
        packetData.insert(packetData.end(), tuple.S_Drone.value >> 8);
        packetData.insert(packetData.end(), tuple.S_Drone.value & 0xFF);
        packetData.insert(packetData.end(), tuple.chi_Drone.data.begin(), tuple.chi_Drone.data.end());
        packetData.insert(packetData.end(), tuple.C_Drone.begin(), tuple.C_Drone.end());
        
        Ptr<Packet> packet = Create<Packet>(packetData.data(), packetData.size());
        m_socket->Send(packet);
        m_packetsSent++;
        NS_LOG_UNCOND("Drone " << GetNode()->GetId() << " sent signcrypted packet " << m_packetsSent 
                     << " at " << Simulator::Now().GetSeconds() << "s");
        ScheduleNextTx();
    }

    void CancelEvents() {
        Simulator::Cancel(m_sendEvent);
    }

    Ptr<Socket> m_socket;
    Address m_peer;
    uint32_t m_packetSize;
    DataRate m_dataRate;
    EventId m_sendEvent;
    bool m_running;
    uint32_t m_packetsSent;
    SigncryptionParams m_params;
};

static double totalBytes = 0;
void ReceivePacket(Ptr<Socket> socket, SigncryptionParams params) {
    while (Ptr<Packet> packet = socket->Recv()) {
        uint8_t* buffer = new uint8_t[packet->GetSize()];
        packet->CopyData(buffer, packet->GetSize());
        std::vector<uint8_t> packetData(buffer, buffer + packet->GetSize());
        

        SigncryptionTuple tuple;
        tuple.S_Drone = FiniteFieldElement((static_cast<uint64_t>(packetData[0]) << 8) | packetData[1]);
        tuple.chi_Drone.data.assign(packetData.begin() + 2, packetData.begin() + 82);
        tuple.C_Drone.assign(packetData.begin() + 82, packetData.end());
        
        std::vector<uint8_t> decrypted = HeterogeneousUnsigncryption(tuple, params);
        if (!decrypted.empty()) {
            totalBytes += packet->GetSize();
            NS_LOG_UNCOND("Ground station received and unsigncrypted packet of size " 
                         << packet->GetSize() << " bytes at " << Simulator::Now().GetSeconds() << "s");
        }
        delete[] buffer;
    }
}

void LogDronePositions(NodeContainer& drones, Ptr<Node> ground, Gnuplot2dDataset& dataset) {
    double avgDistance = 0;
    Vector groundPos = ground->GetObject<MobilityModel>()->GetPosition();
    for (uint32_t i = 0; i < drones.GetN(); ++i) {
        Vector dronePos = drones.Get(i)->GetObject<MobilityModel>()->GetPosition();
        avgDistance += CalculateDistance(dronePos, groundPos);
    }
    avgDistance /= drones.GetN();
    
    double throughput = (totalBytes * 8.0) / 1000000;
    totalBytes = 0;
    
    NS_LOG_UNCOND("Average distance: " << avgDistance << "m, Throughput: " << throughput << "Mbps");
    dataset.Add(avgDistance, throughput);
    Simulator::Schedule(Seconds(1.0), &LogDronePositions, std::ref(drones), ground, std::ref(dataset));
}

int main(int argc, char *argv[]) {
    uint32_t packetSize = 1000;
    double simulationTime = 60.0;
    std::string dataRate = "54Mbps";
    uint32_t numDrones = 3;
    CommandLine cmd(__FILE__);
    cmd.AddValue("packetSize", "Size of packets", packetSize);
    cmd.AddValue("simulationTime", "Simulation duration", simulationTime);
    cmd.AddValue("dataRate", "WiFi data rate", dataRate);
    cmd.AddValue("numDrones", "Number of drones", numDrones);
    cmd.Parse(argc, argv);

    miracl *mip = mmirsys(100, 10);
    sttd::cout << "MIRACLE!!!!" << sttd::endl;


    SigncryptionParams params;
    params.P = Divisor();
    params.mu_PKGC = FiniteFieldElement(12345);
    params.gamma_PKGC = HECCLibrary::Multiply(params.P, params.mu_PKGC);
    params.lambda_EVTG = FiniteFieldElement(67890);
    params.sigma_EVTG = HECCLibrary::Multiply(params.P, params.lambda_EVTG);
    params.Drone_RID = "Drone1";
    params.eta_Drone = FiniteFieldElement(54321);
    params.beta_Drone = HECCLibrary::Multiply(params.P, params.eta_Drone);
    params.PK_Drone = FiniteFieldElement(params.eta_Drone.value + 11111);

    NodeContainer allNodes;
    allNodes.Create(numDrones + 1);
    Ptr<Node> groundStation = allNodes.Get(0);
    NodeContainer drones;
    for (uint32_t i = 0; i < numDrones; ++i) {
        drones.Add(allNodes.Get(i + 1));
    }

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211a);
    YansWifiPhyHelper wifiPhy;
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiPhy.SetChannel(wifiChannel.Create());
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue("OfdmRate" + dataRate));
    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, allNodes);

    MobilityHelper mobility;
    Ptr<ListPositionAllocator> groundPosAlloc = CreateObject<ListPositionAllocator>();
    groundPosAlloc->Add(Vector(0.0, 0.0, 0.0));
    mobility.SetPositionAllocator(groundPosAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(groundStation);

    Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable>();
    x->SetAttribute("Min", DoubleValue(-50.0));
    x->SetAttribute("Max", DoubleValue(50.0));
    Ptr<UniformRandomVariable> y = CreateObject<UniformRandomVariable>();
    y->SetAttribute("Min", DoubleValue(-50.0));
    y->SetAttribute("Max", DoubleValue(50.0));
    Ptr<ListPositionAllocator> dronePosAlloc = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < numDrones; ++i) {
        dronePosAlloc->Add(Vector(x->GetValue(), y->GetValue(), 10.0));
    }
    mobility.SetPositionAllocator(dronePosAlloc);
    mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                             "Mode", StringValue("Time"),
                             "Time", StringValue("1s"),
                             "Speed", StringValue("ns3::ConstantRandomVariable[Constant=5.0]"),
                             "Bounds", RectangleValue(Rectangle(-200, 200, -200, 200)));
    mobility.Install(drones);

    InternetStackHelper stack;
    stack.Install(allNodes);
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> recvSink = Socket::CreateSocket(groundStation, tid);
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 9);
    recvSink->Bind(local);
    recvSink->SetRecvCallback(MakeBoundCallback(&ReceivePacket, params));

    for (uint32_t i = 0; i < numDrones; ++i) {
        Ptr<SigncryptionUdpSender> sender = CreateObject<SigncryptionUdpSender>();
        Ptr<Socket> senderSocket = Socket::CreateSocket(drones.Get(i), tid);
        InetSocketAddress dest = InetSocketAddress(interfaces.GetAddress(0), 9);
        sender->Setup(senderSocket, dest, packetSize, DataRate("1Mbps"), params);
        drones.Get(i)->AddApplication(sender); 
        sender->SetStartTime(Seconds(1.0 + i * 0.1));
        sender->SetStopTime(Seconds(simulationTime));
    }

    wifiPhy.EnablePcap("multi-drone-signcryption", devices);

    Gnuplot plot("multi-drone-signcryption-throughput.png");
    plot.SetTitle("Signcryption Throughput vs Average Distance (Multiple Drones)");
    plot.SetLegend("Average Distance (m)", "Throughput (Mbps)");
    Gnuplot2dDataset dataset("Drone Data");
    dataset.SetStyle(Gnuplot2dDataset::LINES_POINTS);
    
    Simulator::Schedule(Seconds(1.0), &LogDronePositions, std::ref(drones), groundStation, std::ref(dataset));

    Simulator::Stop(Seconds(simulationTime));
    Simulator::Run();
    
    plot.AddDataset(dataset);
    std::ofstream plotFile("multi-drone-signcryption-throughput.plt");
    plot.GenerateOutput(plotFile);
    plotFile.close();
    
    Simulator::Destroy();
    return 0;
}

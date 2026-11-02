/**
 * @file lte_smoke_test.cpp
 * @brief Minimal ns-3 LTE topology smoke test — no PQC, no sockets.
 *        Used to isolate whether the SIGSEGV is ns-3 internal or our code.
 */
#include <ns3/core-module.h>
#include <ns3/lte-module.h>
#include <ns3/internet-module.h>
#include <ns3/point-to-point-module.h>
#include <ns3/network-module.h>
#include <ns3/mobility-module.h>
#include <ns3/mpi-module.h>
#include "uav_pqc/platform/hal.hpp"
#include "uav_pqc/uav_pqc.hpp"
#include "uav_pqc/app/crypto_manager.hpp"
#include "uav_pqc/app/certificate_authority.hpp"
#include "uav_pqc/app/event_bus.hpp"
#include "uav_pqc/app/configuration_manager.hpp"
#include "uav_pqc/app/session_manager.hpp"
#include "uav_pqc/app/acpe_engine.hpp"
#include "uav_pqc/app/treekem_controller.hpp"
#include <iostream>

using namespace ns3;

int main(int argc, char* argv[])
{
    MpiInterface::Enable(&argc, &argv);
    GlobalValue::Bind("SimulatorImplementationType",
                      StringValue("ns3::DefaultSimulatorImpl"));

    auto hal = uav_pqc::platform::make_platform_hal();

    // ── CA Application Setup ─────────────────────────────────────────────────
    uav_pqc::NodeId ca_id{std::byte{0xCA}};
    uav_pqc::app::CryptoManager crypto;
    auto ca_key = crypto.generate_dsa_keypair().value();
    auto ca_key_sim = crypto.generate_dsa_keypair().value();
    std::cout << "[SMOKE] CA keys generated\n";

    uav_pqc::app::CertificateAuthority ca(ca_id, std::move(ca_key));
    auto root_cert_r = ca.generate_root_certificate("Sim_CA", 31536000000ULL, 1000);
    std::cout << "[SMOKE] Root cert generated\n";

    // ── GCS / UAV Application Setup ──────────────────────────────────────────
    auto event_bus = std::make_shared<uav_pqc::app::EventBus>();
    auto config_mgr = std::make_shared<uav_pqc::app::ConfigurationManager>();
    auto crypto_mgr = std::make_shared<uav_pqc::app::CryptoManager>();
    auto session_mgr = std::make_shared<uav_pqc::app::SessionManager>();
    auto acpe_engine = std::make_shared<uav_pqc::app::AcpeEngine>();
    auto treekem_ctrl = std::make_shared<uav_pqc::app::TreeKemController>(
        uav_pqc::protocol::CipherSuite::make_hybrid(uav_pqc::protocol::AeadAlgorithm::AesGcm256)
    );
    std::cout << "[SMOKE] GCS dependencies constructed\n";

    std::cout << "[SMOKE] Creating LTE helpers\n";



    Ptr<LteHelper>              lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper>  epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);

    Ptr<Node> pgw = epcHelper->GetPgwNode();
    std::cout << "[SMOKE] PGW obtained\n";

    InternetStackHelper stack;
    NodeContainer nodes;
    nodes.Create(3); // 0 = CA, 1 = GCS, 2 = UAV


    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    positionAlloc->Add(Vector(0.0, 0.0, 0.0));   // CA
    positionAlloc->Add(Vector(10.0, 0.0, 0.0));  // GCS
    positionAlloc->Add(Vector(20.0, 0.0, 0.0));  // UAV
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // Install internet stack on CA and GCS
    InternetStackHelper infraStack;
    infraStack.Install(nodes.Get(0));
    infraStack.Install(nodes.Get(1));

    // Connect CA and GCS to PGW
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer caDev = p2p.Install(nodes.Get(0), pgw);
    NetDeviceContainer gcsDev = p2p.Install(nodes.Get(1), pgw);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer caInter = address.Assign(caDev);
    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer gcsInter = address.Assign(gcsDev);

    // Install stack on UAV
    InternetStackHelper ueStack;
    ueStack.Install(nodes.Get(2));

    // Create and configure eNB
    NodeContainer enbNodes;
    enbNodes.Create(1);
    mobility.Install(enbNodes);

    NetDeviceContainer enbDevs = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer ueDevs  = lteHelper->InstallUeDevice(NodeContainer(nodes.Get(2)));

    lteHelper->Attach(ueDevs.Get(0), enbDevs.Get(0));

    Ipv4InterfaceContainer ueInter = epcHelper->AssignUeIpv4Address(ueDevs);
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> ueRouting =
        ipv4RoutingHelper.GetStaticRouting(nodes.Get(2)->GetObject<Ipv4>());
    ueRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    std::cout << "[SMOKE] UE IP=" << ueInter.GetAddress(0) << "\n";

    Simulator::Stop(Seconds(3.0));
    std::cout << "[SMOKE] Running...\n";
    Simulator::Run();
    Simulator::Destroy();
    MpiInterface::Disable();
    std::cout << "[SMOKE] Done.\n";
    return 0;
}



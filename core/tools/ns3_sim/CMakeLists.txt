find_package(ns3 REQUIRED COMPONENTS core network internet wifi lr-wpan mobility lte mpi traffic-control applications)

add_executable(uav_pqc_ns3_sim ns3_sim.cpp)
target_link_libraries(uav_pqc_ns3_sim
    PRIVATE
        uav_pqc::core
        ns3::core
        ns3::network
        ns3::internet
        ns3::wifi
        ns3::lr-wpan
        ns3::mobility
        ns3::lte
        ns3::mpi
        ns3::traffic-control
        ns3::applications
        ns3::flow-monitor
)

add_executable(lte_smoke_test lte_smoke_test.cpp)
target_link_libraries(lte_smoke_test
    PRIVATE
        uav_pqc::core
        ns3::core
        ns3::network
        ns3::internet
        ns3::wifi
        ns3::lr-wpan
        ns3::mobility
        ns3::lte
        ns3::mpi
        ns3::traffic-control
        ns3::applications
        ns3::flow-monitor
)



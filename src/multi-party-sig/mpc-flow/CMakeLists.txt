target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        mpc-parallel/mpc_context.cpp
        mpc-parallel/mpc_round.cpp
        mpc-parallel/LazyBCValidator.cpp
        mpc-parallel-v2/mpc_context.cpp
        mpc-parallel-v2/mpc_round.cpp
        common/sid_maker.cpp
        )
# ScadaGuard development rules

- Target Windows x64 with C++20, MSVC, CMake, and vcpkg manifest mode.
- Preserve the read-only boundary: never modify MasterSCADA projects, services, processes, files, or archives.
- Do not invent MasterSCADA process/service names, database schemas, OPC UA endpoints, or NodeIds. All integration details come from validated configuration.
- Keep business logic independent from WinAPI and external data-source implementations.
- Use RAII, `std::chrono`, `std::filesystem`, `std::jthread`, `std::stop_token`, smart pointers, and explicit error handling.
- Do not introduce mutable global state. Service callbacks may only reference a scoped service host instance while SCM owns its lifetime.
- Bind the local API to loopback only. Secrets come from environment variables and must never be logged.
- External MasterSCADA databases are opened read-only; only ScadaGuard's own local database may be migrated or written.
- Add or update tests for changes to validation, data quality, incidents, scheduling, or serialization.
- Build with warnings enabled and keep documentation and `config/config.example.json` aligned with behavior.

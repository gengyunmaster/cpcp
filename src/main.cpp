#include "cli/app.hpp"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        return cpcp::cli::run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "Error: unknown internal error\n";
        return 1;
    }
}

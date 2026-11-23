#include "cli/app.hpp"

#include <CLI/CLI.hpp>

namespace cpcp::cli {

int run(int argc, char** argv) {
    CLI::App app{"Encrypted content-addressed backup CLI", "cpcp"};
    app.set_version_flag("--version", "cpcp " CPCP_VERSION);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& error) {
        const int exit_code = error.get_exit_code();
        app.exit(error);
        return exit_code == 0 ? 0 : 2;
    }

    return 0;
}

}

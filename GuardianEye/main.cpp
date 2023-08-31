#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <initializer_list>
// headers
#include "ProtocolScanner.hpp"
#include "VulnerabilityAnalyzer.hpp"
#include "AutomaticScanScheduler.hpp"
#include "ArgumentSetBuilder.hpp"

void displayLogo() {
    std::string logo =
        "    _____                         _  _                _____\n"
        "   |  __ \\                       | |(_)              |  ___|\n"
        "   | |  \\/ _   _   __ _  _ __  __| | _   __ _  _ __  | |__  _   _   ___\n"
        "   | | __ | | | | / _` || '__|/ _` || | / _` || '_ \\ |  __|| | | | / _ \\\n"
        "   | |_\\ \\| |_| || (_| || |  | (_| || || (_| || | | || |___| |_| ||  __/\n"
        "    \\____/ \\__,_| \\__,_||_|   \\__,_||_| \\__,_||_| |_|\\____/ \\__, | \\___|\n"
        "                                                             __/ |\n"
        "                                                            |___/\n";

    std::cout << logo << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target> [<httpPort>] [<ftpPort>] [<scanInterval>] [<scanDuration>]" << std::endl;
        return 1;
    }

    displayLogo();
    
    ArgumentSetBuilder builder;
    
    // poprzez .addArgument() dokladamy kolejne argumenty jesli chcesz wiedziec jakie parametry po kolei sa wymagane
    // wejdz do pliku ArgumentSetBuilder.cpp i tam w linii 3 masz wszystkie wymagane argumenty
    builder                  // te cyferki wez z discorda
        //.addArgument("target", 6, 15, 0, 255) // argument z linii 28
        .addArgument("httpPort", 2, 5, 1, 65535); // argument z linii 28 // ta linia pobiera argumenty rzeczywiste jak masz linie 26 to argumentem jest
                                            // int argc czyli ilosc podanych argumentow oraz argv[] czyli zbior parametrow np argv["127.0.0.1", "80"]
                                            // w tym przypadku ilosc int argc jest rowna 2 bo mamy 2 argumenty czyli jezeli chcesz odwolac sie do kolejnego
                                            // argumentu dopisujesz argv[numer argumentu] od linii 62 do 73 masz wewnatrz ifow numery argv[] dla kazdego parametru
    // TODO: zadanie ekstra wymagamy argumentu target tylko reszte nie jest wymagana ale jesli w walidatorze zdefiniowalismy jakies dlugosci i zakresy to
    // mimo ze nie saWymagane to walidator sie przywali boWymagaja jakiejs dlugosci, sprobuj dodac logike ktora sprawdzi czy uzywany jest dany argument
    // jesli tak to wtedy dopiero waliduj jesli nie jest uzywany to pomijamy walidacje
    // rozwiazanie jest ponizej zakomentowane wystarczy je odkomentowac dostosowac te powyzej tzn usunac zbedne fragmenty
    
    std::vector<std::string> arguments;
    arguments.push_back(argv[1]);
    arguments.push_back(argv[2]);
    
    std::string target = argv[1];
    // defaults
    int httpPort = 80;
    int ftpPort = 21;
    int scanInterval = 60;
    int scanDuration = 300;
    // end defaults

    if (argc >= 3) {
//        builder.addArgument("httpPort", 2, 5, 1, 65535);
//        arguments.push_back(argv[2]);
        httpPort = std::stoi(argv[2]);
    }
    if (argc >= 4) {
        ftpPort = std::stoi(argv[3]);
    }
    if (argc >= 5) {
        scanInterval = std::stoi(argv[4]);
    }
    if (argc >= 6) {
        scanDuration = std::stoi(argv[5]);
    }
    
    builder.addArgumentSet(arguments);
    builder.validateArguments();


    ProtocolScanner scanner;
    AutomaticScanScheduler scheduler(scanner, target, httpPort, ftpPort, scanInterval, scanDuration);
    std::thread schedulerThread(scheduler);

    std::this_thread::sleep_for(std::chrono::seconds(scanDuration));
    schedulerThread.join();

    VulnerabilityAnalyzer analyzer;
    std::vector<IdentifiedService> identifiedServices;

    int ports[] = {httpPort, ftpPort};

    for (int port : ports) {
        identifiedServices.push_back(analyzer.identifyService(port));
    }

    std::cout << "Identified Services:" << std::endl;
    for (const IdentifiedService& service : identifiedServices) {
        std::cout << "Port: " << service.port << ": " << service.service << std::endl;
    }

    return 0;
}

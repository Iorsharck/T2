#include "logger.h"
#include <iostream>
#include <fstream>

using json = nlohmann::json;

JSONLogger::JSONLogger(const std::string& file)
{
    logFile = file;
}

void JSONLogger::logJSON(const std::string& input_JSON)
{
    std::lock_guard<std::mutex> lock(logMutex);

    try
    {
        // Parse input JSON
        json input = json::parse(input_JSON);

        std::cout << "Received JSON:" << std::endl;
        std::cout << input.dump(4) << std::endl;

        json logData;

        std::ifstream inFile(logFile);

        if(inFile.good())
        {
            try
            {
                inFile >> logData;
            }
            catch(...)
            {
                std::cerr << "Warning: logs_JSON corrupted. Reinitializing." << std::endl;
                logData = json::array();
            }
        }
        else
        {
            if(errno == EACCES)
            {
                std::cerr << "Error: Permission denied reading log file." << std::endl;
                return;
            }

            logData = json::array();
        }

        inFile.close();

        if(!logData.is_array())
        {
            std::cerr << "Error: log file does not contain JSON array." << std::endl;
            return;
        }

        logData.push_back(input);

        std::ofstream outFile(logFile);

        if(!outFile)
        {
            std::cerr << "Error: Cannot write to log file (permissions?)." << std::endl;
            return;
        }

        outFile << logData.dump(4);

        outFile.close();
    }
    catch(const json::parse_error& e)
    {
        std::cerr << "Error: Invalid JSON input -> " << e.what() << std::endl;
    }
    catch(...)
    {
        std::cerr << "Unexpected error while logging JSON." << std::endl;
    }
}
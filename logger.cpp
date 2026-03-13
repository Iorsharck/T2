#include "logger.h"
#include <fstream>
#include <iostream>

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
        json input = json::parse(input_JSON);

        std::cout << input.dump(4) << std::endl;

        json logData;

        std::ifstream in(logFile);

        if(in.good())
        {
            try
            {
                in >> logData;
            }
            catch(...)
            {
                logData = json::array();
            }
        }
        else
        {
            logData = json::array();
        }

        in.close();

        logData.push_back(input);

        std::ofstream out(logFile);

        if(!out)
        {
            std::cerr << "Error writing log file\n";
            return;
        }

        out << logData.dump(4);
    }
    catch(...)
    {
        std::cerr << "Invalid JSON input\n";
    }
}

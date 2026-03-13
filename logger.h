#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <mutex>
#include <nlohmann/json.hpp>

class JSONLogger
{
private:
    std::string logFile;
    std::mutex logMutex;

public:
    JSONLogger(const std::string& file);
    void logJSON(const std::string& input_JSON);
};

#endif
